use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::FieldVar};
use ark_std::vec::Vec;
use crate::MiMCParameters;

mod traits;
// pub use traits::*;

#[derive(Debug, Clone)]
pub struct MiMCVar<F: PrimeField, P: MiMCParameters> {
    pub num_outputs: usize,
    pub k: FpVar<F>,
    pub round_keys: Vec<FpVar<F>>,
    params: PhantomData<P>,
}

impl<F: PrimeField, P: MiMCParameters> MiMCVar<F, P> {
    pub fn new(num_outputs: usize, k: FpVar<F>, round_keys: Vec<FpVar<F>>) -> Self {
        assert_eq!(round_keys.len(), P::ROUNDS, "Invalid round keys length");
        Self {
            num_outputs,
            params: PhantomData,
            k,
            round_keys,
        }
    }
}

impl<F: PrimeField, P: MiMCParameters> MiMCVar<F, P> {
    pub fn permute_feistel(&self, state: Vec<FpVar<F>>) -> Vec<FpVar<F>> {
        let mut r = FpVar::zero();
        let mut c = FpVar::zero();
        for s in state.into_iter() {
            r = &r + &s;
            (r, c) = self.feistel(r, c);
        }
        let mut outputs = vec![r.clone()];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    (r, c) = self.feistel(r.clone(), c);
                    outputs.push(r.clone());
                }
                outputs
            }
        }
    }

    fn feistel(&self, left: FpVar<F>, right: FpVar<F>) -> (FpVar<F>, FpVar<F>) {
        let mut x_l = left;
        let mut x_r = right;
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => &self.k + &x_l,
                false => &self.k + &x_l + &self.round_keys[i],
            };
            let mut tn = FpVar::one();
            (0..P::EXPONENT).for_each(|_| tn = &tn * &t);
            (x_l, x_r) = match i < P::ROUNDS - 1 {
                true => (&x_r + &tn, x_l),
                false => (x_l, &x_r + &tn),
            };
        }
        (x_l, x_r)
    }

    pub fn permute_non_feistel(&self, state: Vec<FpVar<F>>) -> Vec<FpVar<F>> {
        let mut r = self.k.clone();
        for s in state.into_iter() {
            r = &r + &s + &self.non_feistel(&s, &r);
        }
        let mut outputs = vec![r.clone()];
        match self.num_outputs {
            0 | 1 => outputs,
            _ => {
                for _ in 1..self.num_outputs {
                    r = &r + &self.non_feistel(&r, &r);
                    outputs.push(r.clone());
                }
                outputs
            }
        }
    }

    fn non_feistel(&self, x: &FpVar<F>, k: &FpVar<F>) -> FpVar<F> {
        let mut r = FpVar::zero();
        for i in 0..P::ROUNDS {
            let t = match i == 0 {
                true => k + x,
                false => k + r + &self.round_keys[i],
            };
            let mut tn = FpVar::one();
            (0..P::EXPONENT).for_each(|_| tn = &tn * &t);
            r = tn;
        }
        r + k
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bls12_377::Fr;
    use ark_crypto_primitives::crh::{constraints::TwoToOneCRHSchemeGadget, TwoToOneCRHScheme, CRHScheme, poseidon::{constraints::TwoToOneCRHGadget, TwoToOneCRH}};
    // use ark_ff::to_bytes;
    use ark_r1cs_std::{
        fields::fp::FpVar,
        prelude::{AllocVar, EqGadget, FieldVar},
        R1CSVar, ToBytesGadget,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    use crate::constraints::traits::{MiMCNonFeistelCRHSchemeGadget, MiMCNonFeistelCRH, MiMCParameters};

    use super::MiMCVar;

    #[derive(Clone, Default)]
    struct MiMCMock;

    impl MiMCParameters for MiMCMock {
        const ROUNDS: usize = 5;
        const EXPONENT: usize = 5;
    }

    // #[test]
    // fn constraints_feistel() -> Result<(), Box<dyn Error>> {
    //     let rng = &mut test_rng();
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let mimc = <MiMCFeistelCRH<Fr, MiMCMock> as CRHScheme>::setup(rng)?;

    //     let x_l = Fr::from(20);
    //     let x_r = Fr::from(200);
    //     let hashed = <MiMCFeistelCRH<Fr, MiMCMock> as TwoToOneCRHScheme>::evaluate(
    //         &mimc,
    //         &to_bytes!(x_l)?,
    //         &to_bytes!(x_r)?,
    //     )?;

    //     let x_l_var = FpVar::new_witness(cs.clone(), || Ok(x_l))?;
    //     let x_r_var = FpVar::new_witness(cs.clone(), || Ok(x_r))?;
    //     let k_var = FpVar::new_input(cs.clone(), || Ok(mimc.k))?;

    //     let round_keys = Vec::<FpVar<Fr>>::new_constant(cs, mimc.round_keys)?;
    //     let mimc_var = MiMCVar::<_, MiMCMock>::new(1, k_var, round_keys);
    //     let hashed_var = <MiMCFeistelCRHGadget<_, MiMCMock> as TwoToOneCRHGadget<
    //         MiMCFeistelCRH<_, _>,
    //         _,
    //     >>::evaluate(
    //         &mimc_var, &x_l_var.to_bytes()?, &x_r_var.to_bytes()?
    //     )?;

    //     assert!(FpVar::constant(hashed).is_eq(&hashed_var)?.value()?);

    //     Ok(())
    // }

    #[test]
    fn constraints_non_feistel() -> Result<(), Box<dyn Error>> {
        use ark_serialize::CanonicalSerialize;

        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mimc = <MiMCNonFeistelCRH<Fr, MiMCMock> as CRHScheme>::setup(rng)?;

        let x_l = Fr::from(20);
        let mut x_l_bytes = vec![];
        x_l.serialize_compressed(&mut x_l_bytes);
        
        let x_r = Fr::from(200);
        let mut x_r_bytes = vec![];
        x_r.serialize_compressed(&mut x_r_bytes);
        let hashed = <MiMCNonFeistelCRH<Fr, MiMCMock> as TwoToOneCRHScheme>::evaluate(
            &mimc,
            x_l_bytes,
            x_r_bytes,
        )?;

        let x_l_var = FpVar::new_witness(cs.clone(), || Ok(x_l))?;
        let x_r_var = FpVar::new_witness(cs.clone(), || Ok(x_r))?;
        let k_var = FpVar::new_input(cs.clone(), || Ok(mimc.k))?;

        let round_keys = Vec::<FpVar<Fr>>::new_constant(cs, mimc.round_keys)?;
        let mimc_var = MiMCVar::<_, MiMCMock>::new(1, k_var, round_keys);
        let hashed_var =
            <MiMCNonFeistelCRHSchemeGadget<_, MiMCMock> as TwoToOneCRHSchemeGadget<
                MiMCNonFeistelCRH<_, _>,
                _,
            >>::evaluate(&mimc_var, &x_l_var.to_bytes()?, &x_r_var.to_bytes()?)?;

        assert!(FpVar::constant(hashed).is_eq(&hashed_var)?.value()?);

        Ok(())
    }
}
