/// Stable shell contract for top-level navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimaryView {
    Workspace,
    Code,
    Chat,
    Models,
    Agents,
    Media,
    Jobs,
    Extensions,
    Settings,
}

impl PrimaryView {
    pub const ALL: [PrimaryView; 9] = [
        PrimaryView::Workspace,
        PrimaryView::Code,
        PrimaryView::Chat,
        PrimaryView::Models,
        PrimaryView::Agents,
        PrimaryView::Media,
        PrimaryView::Jobs,
        PrimaryView::Extensions,
        PrimaryView::Settings,
    ];

    pub const fn title(self) -> &'static str {
        match self {
            PrimaryView::Workspace => "Workspace",
            PrimaryView::Code => "Code",
            PrimaryView::Chat => "Chat",
            PrimaryView::Models => "Models",
            PrimaryView::Agents => "Agents",
            PrimaryView::Media => "Media",
            PrimaryView::Jobs => "Jobs",
            PrimaryView::Extensions => "Extensions",
            PrimaryView::Settings => "Settings",
        }
    }
}
