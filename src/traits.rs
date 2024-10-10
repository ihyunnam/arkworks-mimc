use rand::rngs::OsRng;
use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{crh::{sha256::digest::typenum::Len, CRHScheme, TwoToOneCRHScheme}, Error};
use ark_ff::{PrimeField};
use ark_std::iterable::Iterable;

use crate::{utils::to_field_elements, MiMC, MiMCParameters};

#[derive(Debug, Default, Clone, Copy)]
pub struct MiMCFeistelCRH<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

#[derive(Debug, Default, Clone, Copy)]
pub struct MiMCNonFeistelCRH<F: PrimeField, P: MiMCParameters>(PhantomData<F>, PhantomData<P>);

impl<F: PrimeField, P: MiMCParameters> Eq for MiMC<F, P> {}

impl<F: PrimeField, P: MiMCParameters> PartialEq for MiMC<F, P> {
    fn eq(&self, other: &Self) -> bool {
        self.num_outputs == other.num_outputs
            && self.k == other.k
            && self.round_keys == other.round_keys
            && self.params == other.params
    }
}

impl<F: PrimeField, P: MiMCParameters> std::fmt::Debug for MiMC<F, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiMC")
            .field("num_outputs", &self.num_outputs)
            .field("k", &self.k)
            .field("round_keys", &self.round_keys)
            .field("params", &self.params)
            .finish()
    }
}
// const INPUT_SIZE_BITS: usize = <F::Params as FpParameters>::CAPACITY as usize;
// impl<F: PrimeField, P: MiMCParameters> CRHScheme for MiMCFeistelCRH<F, P> {
//     type Input = [u8];
//     type Output = F;

//     type Parameters = MiMC<F, P>;

//     fn setup<R: ark_std::rand::Rng>(
//         r: &mut R,
//     ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
//         Ok(Self::Parameters {
//             num_outputs: 1,
//             params: PhantomData,
//             k: F::rand(r),
//             round_keys: (0..P::ROUNDS).map(|_| F::rand(r)).collect::<Vec<_>>(),
//         })
//     }

//     fn evaluate(
//         parameters: &Self::Parameters,
//         input: &[u8],
//     ) -> Result<Self::Output, ark_crypto_primitives::Error> {
//         let fields: Vec<F> = to_field_elements(input);
//         Ok(parameters.permute_feistel(fields)[0])
//     }
// }

// impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHScheme for MiMCFeistelCRH<F, P> {

//     type Input = [u8];
//     type Output = F;

//     type Parameters = MiMC<F, P>;

//     fn setup<R: ark_std::rand::Rng>(
//         r: &mut R,
//     ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
//         <Self as CRH>::setup(r)
//     }

//     fn evaluate(
//         parameters: &Self::Parameters,
//         left_input: &[u8],
//         right_input: &[u8],
//     ) -> Result<Self::Output, ark_crypto_primitives::Error> {
//         assert_eq!(left_input.len(), right_input.len());
//         let chained: Vec<_> = left_input
//             .iter()
//             .chain(right_input.iter())
//             .copied()
//             .collect();
//         <Self as CRH>::evaluate(parameters, &chained)
//     }
// }

// const INPUT_SIZE_BITS: usize = <F::Params as FpParameters>::CAPACITY as usize;
const INPUT_SIZE_BITS: usize = 256;     // capacity(?) for bn254::Fr
impl<F: PrimeField, P: MiMCParameters> CRHScheme for MiMCNonFeistelCRH<F, P> {
    type Input = [u8];
    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        Ok(Self::Parameters {
            num_outputs: 1,
            params: PhantomData,
            k: F::rand(r),
            round_keys: (0..P::ROUNDS).map(|_| F::rand(r)).collect::<Vec<_>>(),
        })
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let input = input.borrow();
        let fields: Vec<F> = to_field_elements(input);
        Ok(parameters.permute_non_feistel(fields)[0])
    }
}

// const INPUT_SIZE_BITS: usize = 32;
const LEFT_INPUT_SIZE_BITS: usize = INPUT_SIZE_BITS;
const RIGHT_INPUT_SIZE_BITS: usize = INPUT_SIZE_BITS;

impl<F: PrimeField, P: MiMCParameters> TwoToOneCRHScheme for MiMCNonFeistelCRH<F, P> {
    type Input = [u8];
    type Output = F;

    type Parameters = MiMC<F, P>;

    fn setup<R: ark_std::rand::Rng>(
        r: &mut R,
    ) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
        <Self as CRHScheme>::setup(r)
    }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();
        assert_eq!(left_input.len(), right_input.len());
        let chained: Vec<_> = left_input
            .iter()
            .chain(right_input.iter())
            .copied()
            .collect();
        <Self as CRHScheme>::evaluate(parameters, chained)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let rng = &mut OsRng;
        Ok(F::rand(rng))
    }
}
