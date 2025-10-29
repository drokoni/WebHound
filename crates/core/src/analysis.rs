// общий интерфейс путей, чтобы его могли реализовать разные раннеры
pub trait PathsLike {
    fn screenshots_dir(&self) -> &std::path::Path;
    fn jsscripts_dir(&self)   -> &std::path::Path;
    fn assets_dir(&self)      -> &std::path::Path;
}
