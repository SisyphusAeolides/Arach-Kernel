//! Hermes bindings for the shared bounded service calculus.
//!
//! The implementation lives in `slope` so Arach command admission and Crest
//! frame prediction use the same min-plus and conformal machinery.

pub use slope::service_calculus::{
    AdmissionCertificate as HermesAdmissionCertificate, AdmissionFault as HermesAdmissionFault,
    ServiceCurve as HermesServiceCurve,
};

pub type HermesServiceController = slope::service_calculus::ServiceController<32>;
