//! Hermes bindings for the shared bounded service calculus.
//!
//! The implementation is part of Arach Kernel so command admission and frame
//! prediction use the same min-plus and conformal machinery.

pub use crate::arach_service_calculus::{
    AdmissionCertificate as HermesAdmissionCertificate, AdmissionFault as HermesAdmissionFault,
    ServiceCurve as HermesServiceCurve,
};

pub type HermesServiceController = crate::arach_service_calculus::ServiceController<32>;
