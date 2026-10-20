//! UI themes, persisted through the layered Zentrion configuration.

use ratatui::style::Color;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Theme {
    pub name: String,
    pub primary: Color,
    pub secondary: Color,
    pub accent: Color,
    pub background: Color,
    pub surface: Color,
    pub text: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::named("zentrion").expect("built-in theme")
    }
}

impl Theme {
    pub fn named(name: &str) -> Option<Self> {
        let key = name.trim().to_ascii_lowercase();
        let theme = match key.as_str() {
            "zentrion" | "default" | "cyan" => Self {
                name: "zentrion".into(),
                primary: Color::Cyan,
                secondary: Color::DarkGray,
                accent: Color::Yellow,
                background: Color::Reset,
                surface: Color::Black,
                text: Color::White,
                success: Color::Green,
                warning: Color::Yellow,
                error: Color::Red,
            },
            "cyberpunk" | "neon" => Self {
                name: "cyberpunk".into(),
                primary: Color::Magenta,
                secondary: Color::Cyan,
                accent: Color::Yellow,
                background: Color::Black,
                surface: Color::Rgb(18, 4, 28),
                text: Color::Rgb(240, 240, 255),
                success: Color::Rgb(0, 255, 170),
                warning: Color::Rgb(255, 200, 0),
                error: Color::Rgb(255, 60, 90),
            },
            "dracula" => Self {
                name: "dracula".into(),
                primary: Color::Rgb(189, 147, 249),
                secondary: Color::Rgb(98, 114, 164),
                accent: Color::Rgb(255, 121, 198),
                background: Color::Rgb(40, 42, 54),
                surface: Color::Rgb(30, 32, 42),
                text: Color::Rgb(248, 248, 242),
                success: Color::Rgb(80, 250, 123),
                warning: Color::Rgb(241, 250, 140),
                error: Color::Rgb(255, 85, 85),
            },
            "gruvbox" => Self {
                name: "gruvbox".into(),
                primary: Color::Rgb(215, 153, 33),
                secondary: Color::Rgb(146, 131, 116),
                accent: Color::Rgb(104, 157, 106),
                background: Color::Rgb(40, 40, 40),
                surface: Color::Rgb(29, 32, 33),
                text: Color::Rgb(235, 219, 178),
                success: Color::Rgb(152, 151, 26),
                warning: Color::Rgb(250, 189, 47),
                error: Color::Rgb(204, 36, 29),
            },
            "nord" => Self {
                name: "nord".into(),
                primary: Color::Rgb(136, 192, 208),
                secondary: Color::Rgb(76, 86, 106),
                accent: Color::Rgb(180, 142, 173),
                background: Color::Rgb(46, 52, 64),
                surface: Color::Rgb(59, 66, 82),
                text: Color::Rgb(236, 239, 244),
                success: Color::Rgb(163, 190, 140),
                warning: Color::Rgb(235, 203, 139),
                error: Color::Rgb(191, 97, 106),
            },
            "matrix" | "green" => Self {
                name: "matrix".into(),
                primary: Color::Rgb(0, 255, 70),
                secondary: Color::Rgb(0, 120, 40),
                accent: Color::Rgb(180, 255, 180),
                background: Color::Black,
                surface: Color::Rgb(0, 16, 4),
                text: Color::Rgb(190, 255, 190),
                success: Color::Rgb(0, 255, 70),
                warning: Color::Rgb(200, 255, 120),
                error: Color::Rgb(255, 80, 80),
            },
            "solarized" | "solarized-dark" => Self {
                name: "solarized-dark".into(),
                primary: Color::Rgb(38, 139, 210),
                secondary: Color::Rgb(88, 110, 117),
                accent: Color::Rgb(211, 54, 130),
                background: Color::Rgb(0, 43, 54),
                surface: Color::Rgb(7, 54, 66),
                text: Color::Rgb(253, 246, 227),
                success: Color::Rgb(133, 153, 0),
                warning: Color::Rgb(181, 137, 0),
                error: Color::Rgb(220, 50, 47),
            },
            _ => return None,
        };
        Some(theme)
    }

    pub fn available() -> &'static [&'static str] {
        &[
            "zentrion",
            "cyberpunk",
            "dracula",
            "gruvbox",
            "nord",
            "matrix",
            "solarized-dark",
        ]
    }

    /// Persist a theme name into the user config layer (never secrets).
    pub fn persist(name: &str) -> anyhow::Result<()> {
        let theme = Self::named(name).ok_or_else(|| anyhow::anyhow!("unknown theme `{name}`"))?;
        let config_dir = z_core::config::user_config_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine the user config directory"))?;
        std::fs::create_dir_all(&config_dir)?;
        let path = config_dir.join("config.yaml");
        let mut config = z_core::config::Config::load_layer(&path)
            .map_err(|e| anyhow::anyhow!("cannot read existing config: {e}"))?
            .unwrap_or_default();
        config.theme = theme.name.clone();
        let text = serde_yaml::to_string(&config)?;
        z_core::fs::write_text(&path, &text)
            .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", path.display()))?;
        Ok(())
    }

    /// Load the theme selected by `ZENTRION_THEME` or the user config.
    /// Invalid values fall back to the default theme instead of failing the UI.
    pub fn load() -> Self {
        if let Ok(name) = std::env::var("ZENTRION_THEME") {
            if !name.trim().is_empty() {
                if let Some(theme) = Self::named(&name) {
                    return theme;
                }
            }
        }

        if let Some(config_dir) = z_core::config::user_config_dir() {
            let path = config_dir.join("config.yaml");
            if let Ok(Some(config)) = z_core::config::Config::load_layer(&path) {
                if let Some(theme) = Self::named(&config.theme) {
                    return theme;
                }
            }
        }

        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_theme_exists() {
        for name in Theme::available() {
            assert!(Theme::named(name).is_some(), "missing theme {name}");
        }
    }

    #[test]
    fn theme_names_are_case_insensitive() {
        assert_eq!(Theme::named("DRACULA").unwrap().name, "dracula");
        assert!(Theme::named("does-not-exist").is_none());
    }
}
