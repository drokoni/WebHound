pub mod report;
pub mod server;
pub mod templates;

pub use report::{render_prediction_report_html, write_prediction_report_html};
pub use server::server;
pub use templates::PREDICTION_REPORT_HTML;
