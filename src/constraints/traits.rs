use std::marker::PhantomData;

use ark_crypto_primitives::crh::{TwoToOneCRHSchemeGadget, CRHSchemeGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::{FieldVar, fp::FpVar}, prelude::{AllocVar, EqGadget}, uint8::UInt8, R1CSVar
};
use ark_relations::r1cs::SynthesisError;

use crate::{
    utils::to_field_elements_r1cs, MiMC, MiMCNonFeistelCRH, MiMCParameters,
};

use super::MiMCVar;

#[derive(Debug, Clone, Copy, Default)]
pub struct MiMCFeistelCRHSchemeGadget<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

#[derive(Debug, Clone, Copy, Default)]
pub struct MiMCNonFeistelCRHSchemeGadget<F: PrimeField, P: MiMCParameters>(
    PhantomData<F>,
    PhantomData<P>,
);

impl<F: PrimeField, P: MiMCParameters> AllocVar<MiMC<F, P>, F> for MiMCVar<F, P> {
    fn new_variable<T: std::borrow::Borrow<MiMC<F, P>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let mimc = f()?.borrow().clone();
        let cs = cs.into().cs();
        Ok(Self {
            num_outputs: mimc.num_outputs,
            params: PhantomData,
            k: FpVar::new_variable(cs.clone(), || Ok(mimc.k), mode)?,
            round_keys: mimc
                .round_keys
                .into_iter()
                // .map(|e| -> Result<_, _> { FpVar::new_variable(cs.clone(), || Ok(e), mode) })
                .map(|e| -> Result<_, _> { FpVar::new_variable(cs.clone(), || Ok(e), ark_r1cs_std::prelude::AllocationMode::Constant) })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl<F: PrimeField, P: MiMCParameters> R1CSVar<F> for MiMCVar<F, P> {
    type Value = MiMC<F, P>;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<F> {
        self.k.cs()
    }

    fn value(&self) -> Result<Self::Value, ark_relations::r1cs::SynthesisError> {
        Ok(MiMC {
            num_outputs: self.num_outputs,
            k: self.k.value()?,
            round_keys: self.round_keys.value()?,
            params: PhantomData,
        })
    }
}

impl<F: PrimeField, P: MiMCParameters> EqGadget<F> for MiMCVar<F, P> {
    fn is_eq(
        &self,
        other: &Self,
    ) -> Result<ark_r1cs_std::prelude::Boolean<F>, ark_relations::r1cs::SynthesisError> {
        self.k
            .is_eq(&other.k)?
            .and(&self.round_keys.is_eq(&other.round_keys)?)
    }
}

// impl<F: PrimeField, P: MiMCParameters> CRHSchemeGadget<MiMCFeistelCRH<F, P>, F>
//     for MiMCFeistelCRHSchemeGadget<F, P>
// {
//     type OutputVar = FpVar<F>;
//     type InputVar = [UInt8<F>];
//     type ParametersVar = MiMCVar<F, P>;

//     fn evaluate(
//         parameters: &Self::ParametersVar,
//         input: &[ark_r1cs_std::uint8::UInt8<F>],
//     ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
//         let fields: Vec<FpVar<F>> = to_field_elements_r1cs(input)?;
//         Ok(parameters.permute_feistel(fields)[0].clone())
//     }
// }

// impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHSchemeGadget<MiMCFeistelCRH<F, P>, F>
//     for MiMCFeistelCRHSchemeGadget<F, P>
// {
//     type OutputVar = FpVar<F>;
//     type InputVar = [UInt8<F>];
//     type ParametersVar = MiMCVar<F, P>;

//     fn evaluate(
//         parameters: &Self::ParametersVar,
//         left_input: &[ark_r1cs_std::uint8::UInt8<F>],
//         right_input: &[ark_r1cs_std::uint8::UInt8<F>],
//     ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
//         assert_eq!(left_input.len(), right_input.len());
//         let chained: Vec<_> = left_input
//             .iter()
//             .chain(right_input.iter())
//             .cloned()
//             .collect();

//         <Self as CRHSchemeGadget<_, _>>::evaluate(parameters, &chained)
//     }

//     fn compress() {}
// }

impl<F: PrimeField, P: MiMCParameters> CRHSchemeGadget<MiMCNonFeistelCRH<F, P>, F>
    for MiMCNonFeistelCRHSchemeGadget<F, P>
{
    type OutputVar = FpVar<F>;
    type InputVar = [UInt8<F>];
    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        let fields: Vec<FpVar<F>> = to_field_elements_r1cs(input)?;
        Ok(parameters.permute_non_feistel(fields)[0].clone())
    }
}

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHSchemeGadget<MiMCNonFeistelCRH<F, P>, F>
    for MiMCNonFeistelCRHSchemeGadget<F, P>
{
    type OutputVar = FpVar<F>;
    type InputVar = [UInt8<F>];
    type ParametersVar = MiMCVar<F, P>;

    fn evaluate(
        parameters: &Self::ParametersVar,
        left_input: &[ark_r1cs_std::uint8::UInt8<F>],
        right_input: &[ark_r1cs_std::uint8::UInt8<F>],
    ) -> Result<Self::OutputVar, ark_relations::r1cs::SynthesisError> {
        assert_eq!(left_input.len(), right_input.len());
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .cloned()
            .collect();

        <Self as CRHSchemeGadget<_, _>>::evaluate(parameters, &chained)
    }
    
    fn compress(
        parameters: &Self::ParametersVar,
        left_input: &Self::OutputVar,
        right_input: &Self::OutputVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        Ok(FpVar::<F>::zero())
    }

}
