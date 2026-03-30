use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let icon_png = forge_icon_png_path();
    println!("cargo:rerun-if-changed={}", icon_png.display());

    #[cfg(target_os = "windows")]
    {
        if let Err(error) = configure_windows_icon(&icon_png) {
            panic!("failed to configure Forge icon resources: {error}");
        }
    }
}

fn forge_icon_png_path() -> PathBuf {
    let manifest_dir = match env::var("CARGO_MANIFEST_DIR") {
        Ok(value) => PathBuf::from(value),
        Err(_) => PathBuf::from("."),
    };
    match manifest_dir.parent().and_then(Path::parent) {
        Some(workspace_root) => workspace_root.join("image").join("Forge.png"),
        None => PathBuf::from("image/Forge.png"),
    }
}

#[cfg(target_os = "windows")]
fn configure_windows_icon(icon_png: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !icon_png.exists() {
        return Err(format!("icon image not found at {}", icon_png.display()).into());
    }

    let workspace_icon_ico = icon_png.with_extension("ico");
    write_multi_size_ico(icon_png, &workspace_icon_ico)?;

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let out_icon_ico = out_dir.join("forge_generated.ico");
    write_multi_size_ico(icon_png, &out_icon_ico)?;

    let out_icon_ico_string = out_icon_ico.to_string_lossy().into_owned();
    if let Err(error) = winres::WindowsResource::new()
        .set_icon(&out_icon_ico_string)
        .compile()
    {
        println!(
            "cargo:warning=Forge icon embedding skipped (resource compiler unavailable): {error}"
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_multi_size_ico(
    icon_png: &Path,
    icon_ico_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = image::open(icon_png)?;
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for edge in [16u32, 24, 32, 40, 48, 64, 128, 256] {
        let resized = source.resize_exact(edge, edge, image::imageops::FilterType::Lanczos3);
        let rgba = resized.into_rgba8().into_raw();
        let icon_image = ico::IconImage::from_rgba_data(edge, edge, rgba);
        let icon_entry = ico::IconDirEntry::encode(&icon_image)?;
        icon_dir.add_entry(icon_entry);
    }

    if let Some(parent) = icon_ico_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(icon_ico_path)?;
    icon_dir.write(&mut file)?;
    Ok(())
}
