#[allow(clippy::too_many_arguments)]
fn media_studio_panel(
    queue: Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
    media_prompt: RwSignal<String>,
    media_seed: RwSignal<String>,
    media_batch_size: RwSignal<String>,
    media_status: RwSignal<String>,
    media_gallery: RwSignal<String>,
    media_next_asset_id: RwSignal<u64>,
    video_prompt: RwSignal<String>,
    video_seed: RwSignal<String>,
    video_batch_size: RwSignal<String>,
    video_duration_seconds: RwSignal<String>,
    video_status: RwSignal<String>,
    video_checkpoint_log: RwSignal<String>,
    video_checkpoint_state: Rc<RefCell<HashMap<u64, VideoCheckpointState>>>,
    source_registry: Rc<RefCell<SourceRegistry>>,
) -> impl IntoView {
    let queue_images = {
        let queue = queue.clone();
        let video_checkpoint_state = video_checkpoint_state.clone();
        let source_registry = source_registry.clone();
        move || {
            let prompt = media_prompt.get().trim().to_string();
            if prompt.is_empty() {
                media_status.set(String::from("image queue rejected: prompt is empty"));
                return;
            }

            let image_route = {
                let registry = match source_registry.try_borrow() {
                    Ok(value) => value,
                    Err(error) => {
                        media_status.set(format!("image queue blocked: source registry busy ({error})"));
                        return;
                    }
                };
                match resolve_source_route_for_role(&registry, SourceRole::ImageGeneration) {
                    Ok(route) => route,
                    Err(error) => {
                        media_status
                            .set(format!("image queue blocked: {}", clip_text(&error, 140)));
                        return;
                    }
                }
            };

            let seed = match parse_u64(media_seed.get().as_str(), "seed") {
                Ok(value) => value,
                Err(error) => {
                    media_status.set(format!("image queue rejected: {error}"));
                    return;
                }
            };
            let batch_size = match parse_u32(media_batch_size.get().as_str(), "batch-size") {
                Ok(value) => value,
                Err(error) => {
                    media_status.set(format!("image queue rejected: {error}"));
                    return;
                }
            };
            if batch_size > 32 {
                media_status.set(String::from(
                    "image queue rejected: batch-size must be <= 32 for local safety",
                ));
                return;
            }

            let mut queue_mut = queue.borrow_mut();
            let mut gallery = media_gallery.get();
            let first_asset_id = media_next_asset_id.get();
            let prompt_preview = clip_text(&prompt, 90);
            for index in 0..batch_size {
                let asset_id = first_asset_id.saturating_add(index as u64);
                let current_seed = seed.saturating_add(index as u64);
                let _ = queue_mut.enqueue(
                    format!("image-{asset_id}@{}", image_route.source_id),
                    JobKind::ImageGeneration,
                    JobPriority::Normal,
                );
                gallery.push_str(&format!(
                    "#{} queued | seed={} | source={} ({}) | prompt={}\n",
                    asset_id,
                    current_seed,
                    image_route.source_display_name,
                    format_source_kind_label(image_route.source_kind),
                    prompt_preview
                ));
            }
            media_next_asset_id.set(first_asset_id.saturating_add(batch_size as u64));
            media_gallery.set(clip_text(gallery.trim_end(), 14_000));
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            media_status.set(format!(
                "queued {batch_size} image job(s) from seed {seed} via {} ({})",
                image_route.source_display_name,
                format_source_kind_label(image_route.source_kind)
            ));
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, media_status);
            persist_media_state_with_notice(
                media_prompt,
                media_seed,
                media_batch_size,
                media_gallery,
                media_next_asset_id,
                video_prompt,
                video_seed,
                video_batch_size,
                video_duration_seconds,
                &video_checkpoint_state,
                media_status,
            );
        }
    };

    let clear_gallery = {
        let video_checkpoint_state = video_checkpoint_state.clone();
        move || {
            media_gallery.set(String::new());
            media_status.set(String::from("gallery cleared"));
            persist_media_state_with_notice(
                media_prompt,
                media_seed,
                media_batch_size,
                media_gallery,
                media_next_asset_id,
                video_prompt,
                video_seed,
                video_batch_size,
                video_duration_seconds,
                &video_checkpoint_state,
                media_status,
            );
        }
    };

    let queue_videos = {
        let queue = queue.clone();
        let video_checkpoint_state = video_checkpoint_state.clone();
        let source_registry = source_registry.clone();
        move || {
            let prompt = video_prompt.get().trim().to_string();
            if prompt.is_empty() {
                video_status.set(String::from("video queue rejected: prompt is empty"));
                return;
            }

            let video_route = {
                let registry = match source_registry.try_borrow() {
                    Ok(value) => value,
                    Err(error) => {
                        video_status.set(format!("video queue blocked: source registry busy ({error})"));
                        return;
                    }
                };
                match resolve_source_route_for_role(&registry, SourceRole::VideoGeneration) {
                    Ok(route) => route,
                    Err(error) => {
                        video_status
                            .set(format!("video queue blocked: {}", clip_text(&error, 140)));
                        return;
                    }
                }
            };
            let seed = match parse_u64(video_seed.get().as_str(), "video seed") {
                Ok(value) => value,
                Err(error) => {
                    video_status.set(format!("video queue rejected: {error}"));
                    return;
                }
            };
            let batch_size = match parse_u32(video_batch_size.get().as_str(), "video batch-size") {
                Ok(value) => value,
                Err(error) => {
                    video_status.set(format!("video queue rejected: {error}"));
                    return;
                }
            };
            if batch_size > 8 {
                video_status.set(String::from(
                    "video queue rejected: video batch-size must be <= 8",
                ));
                return;
            }
            let duration_seconds = match parse_u32(
                video_duration_seconds.get().as_str(),
                "video duration-seconds",
            ) {
                Ok(value) => value,
                Err(error) => {
                    video_status.set(format!("video queue rejected: {error}"));
                    return;
                }
            };
            if duration_seconds > 120 {
                video_status.set(String::from(
                    "video queue rejected: duration-seconds must be <= 120",
                ));
                return;
            }

            let mut queue_mut = queue.borrow_mut();
            let mut checkpoints = video_checkpoint_state.borrow_mut();
            let first_asset_id = media_next_asset_id.get();
            let prompt_preview = clip_text(&prompt, 90);
            for index in 0..batch_size {
                let asset_id = first_asset_id.saturating_add(index as u64);
                let current_seed = seed.saturating_add(index as u64);
                let _ = queue_mut.enqueue(
                    format!("video-{asset_id}@{}", video_route.source_id),
                    JobKind::VideoGeneration,
                    JobPriority::Background,
                );
                checkpoints.insert(
                    asset_id,
                    VideoCheckpointState {
                        asset_id,
                        prompt_preview: prompt_preview.clone(),
                        seed: current_seed,
                        duration_seconds,
                        source_id: video_route.source_id.clone(),
                        source_display_name: video_route.source_display_name.clone(),
                        source_kind: video_route.source_kind,
                        progress_percent: 0,
                        state: String::from("queued"),
                    },
                );
            }
            media_next_asset_id.set(first_asset_id.saturating_add(batch_size as u64));
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            video_checkpoint_log.set(format_video_checkpoint_log(&checkpoints));
            video_status.set(format!(
                "queued {batch_size} video job(s), duration={}s seed={} via {} ({})",
                duration_seconds,
                seed,
                video_route.source_display_name,
                format_source_kind_label(video_route.source_kind)
            ));
            drop(checkpoints);
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, video_status);
            persist_media_state_with_notice(
                media_prompt,
                media_seed,
                media_batch_size,
                media_gallery,
                media_next_asset_id,
                video_prompt,
                video_seed,
                video_batch_size,
                video_duration_seconds,
                &video_checkpoint_state,
                video_status,
            );
        }
    };

    let checkpoint_video = {
        let video_checkpoint_state = video_checkpoint_state.clone();
        move || {
            let mut checkpoints = video_checkpoint_state.borrow_mut();
            let mut ordered = checkpoints.keys().copied().collect::<Vec<_>>();
            ordered.sort_unstable();
            let mut updated = None;
            for asset_id in ordered {
                let Some(entry) = checkpoints.get_mut(&asset_id) else {
                    continue;
                };
                if entry.progress_percent >= 100 {
                    continue;
                }
                let next = entry.progress_percent.saturating_add(10).min(100);
                entry.progress_percent = next;
                entry.state = if next == 100 {
                    String::from("checkpoint-complete")
                } else {
                    String::from("checkpointed")
                };
                updated = Some((asset_id, next));
                break;
            }
            video_checkpoint_log.set(format_video_checkpoint_log(&checkpoints));
            match updated {
                Some((asset_id, next)) => {
                    video_status.set(format!("checkpoint saved for video-{asset_id} at {next}%"));
                }
                None => {
                    video_status.set(String::from("checkpoint skipped: no resumable video jobs"));
                }
            }
            drop(checkpoints);
            persist_media_state_with_notice(
                media_prompt,
                media_seed,
                media_batch_size,
                media_gallery,
                media_next_asset_id,
                video_prompt,
                video_seed,
                video_batch_size,
                video_duration_seconds,
                &video_checkpoint_state,
                video_status,
            );
        }
    };

    let resume_video = {
        let queue = queue.clone();
        let video_checkpoint_state = video_checkpoint_state.clone();
        let source_registry = source_registry.clone();
        move || {
            let video_route = {
                let registry = match source_registry.try_borrow() {
                    Ok(value) => value,
                    Err(error) => {
                        video_status.set(format!("resume blocked: source registry busy ({error})"));
                        return;
                    }
                };
                match resolve_source_route_for_role(&registry, SourceRole::VideoGeneration) {
                    Ok(route) => route,
                    Err(error) => {
                        video_status.set(format!("resume blocked: {}", clip_text(&error, 140)));
                        return;
                    }
                }
            };

            let mut checkpoints = video_checkpoint_state.borrow_mut();
            let mut ordered = checkpoints.keys().copied().collect::<Vec<_>>();
            ordered.sort_unstable();
            let mut resumed = None;
            for asset_id in ordered {
                let Some(entry) = checkpoints.get_mut(&asset_id) else {
                    continue;
                };
                if entry.progress_percent >= 100 {
                    continue;
                }
                entry.source_id = video_route.source_id.clone();
                entry.source_display_name = video_route.source_display_name.clone();
                entry.source_kind = video_route.source_kind;
                entry.state = String::from("resumed");
                resumed = Some(asset_id);
                break;
            }

            match resumed {
                Some(asset_id) => {
                    let mut queue_mut = queue.borrow_mut();
                    let _ = queue_mut.enqueue(
                        format!("video-resume-{asset_id}@{}", video_route.source_id),
                        JobKind::VideoGeneration,
                        JobPriority::Foreground,
                    );
                    sync_job_metrics(
                        &queue_mut,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    video_status.set(format!(
                        "resumed video-{asset_id} from checkpoint via {} ({})",
                        video_route.source_display_name,
                        format_source_kind_label(video_route.source_kind)
                    ));
                    drop(queue_mut);
                    persist_job_queue_with_notice(&queue, video_status);
                }
                None => {
                    video_status.set(String::from("resume skipped: no checkpointed video jobs"));
                }
            }
            video_checkpoint_log.set(format_video_checkpoint_log(&checkpoints));
            drop(checkpoints);
            persist_media_state_with_notice(
                media_prompt,
                media_seed,
                media_batch_size,
                media_gallery,
                media_next_asset_id,
                video_prompt,
                video_seed,
                video_batch_size,
                video_duration_seconds,
                &video_checkpoint_state,
                video_status,
            );
        }
    };
    let queue_images = guarded_ui_action("media.queue_images", Some(media_status), queue_images);
    let clear_gallery =
        guarded_ui_action("media.clear_gallery", Some(media_status), clear_gallery);
    let queue_videos = guarded_ui_action("media.queue_videos", Some(video_status), queue_videos);
    let checkpoint_video = guarded_ui_action(
        "media.checkpoint_video",
        Some(video_status),
        checkpoint_video,
    );
    let resume_video = guarded_ui_action("media.resume_video", Some(video_status), resume_video);

    v_stack((
        label(|| "Media Studio"),
        label({
            let source_registry = source_registry.clone();
            move || {
                match source_registry.try_borrow() {
                    Ok(registry) => format!(
                        "route defaults: image={} video={}",
                        format_source_role_default(&registry, SourceRole::ImageGeneration),
                        format_source_role_default(&registry, SourceRole::VideoGeneration),
                    ),
                    Err(_) => "route defaults: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label(|| "Image Studio v1: prompting, seeds, batches, gallery"),
        h_stack((
            label(|| "Prompt"),
            text_input(media_prompt).style(|s| s.min_width(560.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(8.0)),
        h_stack((
            label(|| "Seed"),
            text_input(media_seed).style(|s| s.min_width(100.0).padding(6.0).color(theme::input_text())),
            label(|| "Batch"),
            text_input(media_batch_size).style(|s| s.min_width(80.0).padding(6.0).color(theme::input_text())),
            button("Queue Images").action(queue_images),
            button("Clear Gallery").action(clear_gallery),
        ))
        .style(|s| s.gap(8.0)),
        label(move || format!("Queue depth: {}", queued_jobs.get()))
            .style(|s| s.color(theme::text_secondary())),
        label(move || format!("Running jobs: {}", running_jobs.get()))
            .style(|s| s.color(theme::text_secondary())),
        label(move || format!("Status: {}", media_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        scroll(label(move || {
            let gallery = media_gallery.get();
            if gallery.trim().is_empty() {
                String::from("Gallery is empty. Queue image batches to populate local results.")
            } else {
                gallery
            }
        }))
        .style(|s| {
            s.width_full()
                .height(260.0)
                .padding(8.0)
                .background(theme::surface_1())
        }),
        label(|| "Video Studio v1: long-job queue, checkpointing, resumable execution"),
        h_stack((
            label(|| "Video Prompt"),
            text_input(video_prompt).style(|s| s.min_width(520.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(8.0)),
        h_stack((
            label(|| "Video Seed"),
            text_input(video_seed).style(|s| s.min_width(100.0).padding(6.0).color(theme::input_text())),
            label(|| "Batch"),
            text_input(video_batch_size).style(|s| s.min_width(80.0).padding(6.0).color(theme::input_text())),
            label(|| "Duration(s)"),
            text_input(video_duration_seconds).style(|s| s.min_width(90.0).padding(6.0).color(theme::input_text())),
            button("Queue Videos").action(queue_videos),
            button("Checkpoint +10%").action(checkpoint_video),
            button("Resume Next").action(resume_video),
        ))
        .style(|s| s.gap(8.0)),
        label(move || format!("Video Status: {}", video_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        scroll(label(move || {
            let checkpoints = video_checkpoint_log.get();
            if checkpoints.trim().is_empty() {
                String::from("No video checkpoints yet. Queue a video batch first.")
            } else {
                checkpoints
            }
        }))
        .style(|s| {
            s.width_full()
                .height(180.0)
                .padding(8.0)
                .background(theme::surface_1())
        }),
    ))
    .style(|s| s.size_full().padding(12.0).row_gap(8.0))
}

