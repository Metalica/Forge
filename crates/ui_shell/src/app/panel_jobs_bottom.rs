#[allow(clippy::too_many_arguments)]
fn jobs_panel(
    queue: Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> impl IntoView {
    let jobs_target_id = RwSignal::new(String::new());
    let jobs_filter = RwSignal::new(String::from("all"));
    let jobs_status = RwSignal::new(String::from("jobs view ready"));

    let enqueue_job = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            let job_id = queue_mut.enqueue(
                "Manual jobs-view enqueue",
                JobKind::SystemTask,
                JobPriority::Normal,
            );
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            jobs_status.set(format!("enqueued job #{} from jobs view", job_id.raw()));
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };

    let run_next = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            let id = queue_mut.start_next();
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            match id {
                Some(job_id) => jobs_status.set(format!("started job #{}", job_id.raw())),
                None => jobs_status.set(String::from("run next skipped: no queued jobs")),
            }
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };

    let complete_running = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            if let Some(job_id) = queue_mut.first_running_job() {
                let _ = queue_mut.complete(job_id);
                jobs_status.set(format!("completed job #{}", job_id.raw()));
            } else {
                jobs_status.set(String::from("complete skipped: no running job"));
            }
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };

    let fail_running = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            if let Some(job_id) = queue_mut.first_running_job() {
                let _ = queue_mut.fail(job_id, "jobs-view manual failure");
                jobs_status.set(format!("failed job #{}", job_id.raw()));
            } else {
                jobs_status.set(String::from("fail skipped: no running job"));
            }
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };

    let cancel_target = {
        let queue = queue.clone();
        move || {
            let raw_target = jobs_target_id.get();
            let parsed = match parse_u64(raw_target.as_str(), "job id") {
                Ok(value) => value,
                Err(error) => {
                    jobs_status.set(format!("cancel rejected: {error}"));
                    return;
                }
            };

            let mut queue_mut = queue.borrow_mut();
            let target = queue_mut
                .records_recent(512)
                .into_iter()
                .find(|record| record.id.raw() == parsed)
                .map(|record| record.id);
            match target {
                Some(job_id) => {
                    if queue_mut.cancel(job_id) {
                        jobs_status.set(format!("cancelled job #{}", job_id.raw()));
                    } else {
                        jobs_status.set(format!("cancel failed for job #{parsed}"));
                    }
                }
                None => {
                    jobs_status.set(format!("cancel skipped: job #{parsed} not found"));
                }
            }
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };

    let apply_filter = move || {
        jobs_status.set(format!(
            "filter applied: {}",
            normalize_jobs_filter(jobs_filter.get().as_str())
        ));
    };
    let enqueue_job = guarded_ui_action("jobs.enqueue", Some(jobs_status), enqueue_job);
    let run_next = guarded_ui_action("jobs.run_next", Some(jobs_status), run_next);
    let complete_running = guarded_ui_action(
        "jobs.complete_running",
        Some(jobs_status),
        complete_running,
    );
    let fail_running = guarded_ui_action("jobs.fail_running", Some(jobs_status), fail_running);
    let cancel_target = guarded_ui_action("jobs.cancel_target", Some(jobs_status), cancel_target);
    let apply_filter = guarded_ui_action("jobs.apply_filter", Some(jobs_status), apply_filter);

    v_stack((
        label(|| "Jobs"),
        h_stack((
            button("Enqueue").action(enqueue_job),
            button("Run Next").action(run_next),
            button("Complete Running").action(complete_running),
            button("Fail Running").action(fail_running),
        ))
        .style(|s| s.gap(8.0)),
        h_stack((
            label(|| "Cancel ID"),
            text_input(jobs_target_id).style(|s| s.min_width(120.0).padding(6.0).color(theme::input_text())),
            button("Cancel").action(cancel_target),
            label(|| "Filter"),
            text_input(jobs_filter).style(|s| s.min_width(140.0).padding(6.0).color(theme::input_text())),
            button("Apply Filter").action(apply_filter),
        ))
        .style(|s| s.gap(8.0)),
        h_stack((
            label(move || format!("queued: {}", queued_jobs.get())),
            label(move || format!("running: {}", running_jobs.get())),
            label(move || format!("completed: {}", completed_jobs.get())),
            label(move || format!("failed: {}", failed_jobs.get())),
            label(move || format!("cancelled: {}", cancelled_jobs.get())),
        ))
        .style(|s| s.gap(12.0).color(theme::text_secondary())),
        label({
            let queue = queue.clone();
            move || {
                let _ = (
                    queued_jobs.get(),
                    running_jobs.get(),
                    completed_jobs.get(),
                    failed_jobs.get(),
                    cancelled_jobs.get(),
                );
                match queue.try_borrow() {
                    Ok(queue_ref) => match queue_ref.first_running_job() {
                        Some(job_id) => format!("active job id: {}", job_id.raw()),
                        None => String::from("active job id: none"),
                    },
                    Err(_) => String::from("active job id: busy"),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label(move || format!("Status: {}", jobs_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        scroll(label({
            let queue = queue.clone();
            move || {
                let _ = (
                    queued_jobs.get(),
                    running_jobs.get(),
                    completed_jobs.get(),
                    failed_jobs.get(),
                    cancelled_jobs.get(),
                );
                match queue.try_borrow() {
                    Ok(queue_ref) => format_job_timeline(&queue_ref, jobs_filter.get().as_str(), 36),
                    Err(_) => String::from("job timeline busy; retry in a moment"),
                }
            }
        }))
        .style(|s| {
            s.width_full()
                .height_full()
                .padding(8.0)
                .background(theme::surface_1())
        }),
    ))
    .style(|s| s.size_full().row_gap(8.0))
}

#[allow(clippy::too_many_arguments)]
fn bottom_panel(
    queue: Rc<RefCell<JobQueue>>,
    running_job_id: RwSignal<Option<JobId>>,
    jobs_target_id: RwSignal<String>,
    jobs_filter: RwSignal<String>,
    jobs_status: RwSignal<String>,
    jobs_timeline: RwSignal<String>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> impl IntoView {
    let enqueue_job = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            let job_id =
                queue_mut.enqueue("Phase 1 demo job", JobKind::CodeBuild, JobPriority::Normal);
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            jobs_timeline.set(format_job_timeline(
                &queue_mut,
                jobs_filter.get().as_str(),
                24,
            ));
            jobs_status.set(format!("enqueued demo job #{}", job_id.raw()));
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };
    let run_next = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            let id = queue_mut.start_next();
            running_job_id.set(id);
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            jobs_timeline.set(format_job_timeline(
                &queue_mut,
                jobs_filter.get().as_str(),
                24,
            ));
            match id {
                Some(job_id) => jobs_status.set(format!("started job #{}", job_id.raw())),
                None => jobs_status.set(String::from("run next skipped: no queued jobs")),
            }
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };
    let complete_running = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            let target_running = running_job_id
                .get()
                .or_else(|| queue_mut.first_running_job());
            if let Some(job_id) = target_running {
                let _ = queue_mut.complete(job_id);
                running_job_id.set(queue_mut.first_running_job());
                jobs_status.set(format!("completed job #{}", job_id.raw()));
            } else {
                jobs_status.set(String::from("complete skipped: no running job"));
            }
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            jobs_timeline.set(format_job_timeline(
                &queue_mut,
                jobs_filter.get().as_str(),
                24,
            ));
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };
    let fail_running = {
        let queue = queue.clone();
        move || {
            let mut queue_mut = queue.borrow_mut();
            let target_running = running_job_id
                .get()
                .or_else(|| queue_mut.first_running_job());
            if let Some(job_id) = target_running {
                let _ = queue_mut.fail(job_id, "phase1-demo failure");
                running_job_id.set(queue_mut.first_running_job());
                jobs_status.set(format!("failed job #{}", job_id.raw()));
            } else {
                jobs_status.set(String::from("fail skipped: no running job"));
            }
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            jobs_timeline.set(format_job_timeline(
                &queue_mut,
                jobs_filter.get().as_str(),
                24,
            ));
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };
    let cancel_target = {
        let queue = queue.clone();
        move || {
            let raw_target = jobs_target_id.get();
            let parsed = match parse_u64(raw_target.as_str(), "job id") {
                Ok(value) => value,
                Err(error) => {
                    jobs_status.set(format!("cancel rejected: {error}"));
                    return;
                }
            };

            let mut queue_mut = queue.borrow_mut();
            let target = queue_mut
                .records_recent(512)
                .into_iter()
                .find(|record| record.id.raw() == parsed)
                .map(|record| record.id);
            match target {
                Some(job_id) => {
                    if queue_mut.cancel(job_id) {
                        let next_running = queue_mut.first_running_job();
                        running_job_id.set(next_running);
                        jobs_status.set(format!("cancelled job #{}", job_id.raw()));
                    } else {
                        jobs_status.set(format!("cancel failed for job #{parsed}"));
                    }
                }
                None => {
                    jobs_status.set(format!("cancel skipped: job #{parsed} not found"));
                }
            }
            sync_job_metrics(
                &queue_mut,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            jobs_timeline.set(format_job_timeline(
                &queue_mut,
                jobs_filter.get().as_str(),
                24,
            ));
            drop(queue_mut);
            persist_job_queue_with_notice(&queue, jobs_status);
        }
    };
    let apply_filter = {
        let queue = queue.clone();
        move || {
            match queue.try_borrow() {
                Ok(queue_ref) => {
                    jobs_timeline.set(format_job_timeline(
                        &queue_ref,
                        jobs_filter.get().as_str(),
                        24,
                    ));
                    jobs_status.set(format!(
                        "filter applied: {}",
                        normalize_jobs_filter(jobs_filter.get().as_str())
                    ));
                }
                Err(error) => {
                    jobs_status.set(format!("filter skipped: queue busy ({error})"));
                }
            }
        }
    };
    let enqueue_job = guarded_ui_action("bottom_jobs.enqueue", Some(jobs_status), enqueue_job);
    let run_next = guarded_ui_action("bottom_jobs.run_next", Some(jobs_status), run_next);
    let complete_running = guarded_ui_action(
        "bottom_jobs.complete_running",
        Some(jobs_status),
        complete_running,
    );
    let fail_running = guarded_ui_action(
        "bottom_jobs.fail_running",
        Some(jobs_status),
        fail_running,
    );
    let cancel_target = guarded_ui_action(
        "bottom_jobs.cancel_target",
        Some(jobs_status),
        cancel_target,
    );
    let apply_filter = guarded_ui_action(
        "bottom_jobs.apply_filter",
        Some(jobs_status),
        apply_filter,
    );

    v_stack((
        label(|| "Bottom Stack: Terminal | Logs | Jobs"),
        h_stack((
            button("Enqueue").action(enqueue_job),
            button("Run Next").action(run_next),
            button("Complete").action(complete_running),
            button("Fail").action(fail_running),
        ))
        .style(|s| s.gap(8.0)),
        h_stack((
            label(|| "Target ID"),
            text_input(jobs_target_id).style(|s| s.min_width(90.0).padding(6.0).color(theme::input_text())),
            button("Cancel ID").action(cancel_target),
            label(|| "Filter"),
            text_input(jobs_filter).style(|s| s.min_width(120.0).padding(6.0).color(theme::input_text())),
            button("Apply Filter").action(apply_filter),
        ))
        .style(|s| s.gap(8.0)),
        h_stack((
            label(move || format!("queued: {}", queued_jobs.get())),
            label(move || format!("running: {}", running_jobs.get())),
            label(move || format!("completed: {}", completed_jobs.get())),
            label(move || format!("failed: {}", failed_jobs.get())),
            label(move || format!("cancelled: {}", cancelled_jobs.get())),
        ))
        .style(|s| s.gap(12.0).color(theme::text_secondary())),
        label(move || format!("Jobs Status: {}", jobs_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        label({
            let queue = queue.clone();
            move || {
                let _ = (
                    queued_jobs.get(),
                    running_jobs.get(),
                    completed_jobs.get(),
                    failed_jobs.get(),
                    cancelled_jobs.get(),
                );
                match queue.try_borrow() {
                    Ok(queue_ref) => match queue_ref.first_running_job() {
                        Some(job_id) => format!("active job id: {}", job_id.raw()),
                        None => String::from("active job id: none"),
                    },
                    Err(_) => String::from("active job id: busy"),
                }
            }
        }),
        scroll(label({
            let queue = queue.clone();
            move || {
                let _ = (
                    queued_jobs.get(),
                    running_jobs.get(),
                    completed_jobs.get(),
                    failed_jobs.get(),
                    cancelled_jobs.get(),
                );
                match queue.try_borrow() {
                    Ok(queue_ref) => format_job_timeline(&queue_ref, jobs_filter.get().as_str(), 24),
                    Err(_) => String::from("job timeline busy; retry in a moment"),
                }
            }
        }))
        .style(|s| {
            s.width_full()
                .height(112.0)
                .padding(8.0)
                .background(theme::surface_2())
        }),
    ))
    .style(|s| {
        s.width_full()
            .height(300.0)
            .padding(10.0)
            .row_gap(8.0)
            .background(theme::surface_1())
            .border_top(1.0)
    })
}

fn normalize_jobs_filter(input: &str) -> String {
    let normalized = input.trim().to_lowercase().replace('-', "_");
    if normalized.is_empty() {
        return String::from("all");
    }
    normalized
}

fn format_job_timeline(queue: &JobQueue, filter: &str, limit: usize) -> String {
    let normalized_filter = normalize_jobs_filter(filter);
    let mut lines = Vec::new();
    for record in queue.records_recent(limit.saturating_mul(4).max(24)) {
        if !job_record_matches_filter(&record, normalized_filter.as_str()) {
            continue;
        }
        let mut line = format!(
            "#{} | state={} | kind={} | prio={:?} | name={}",
            record.id.raw(),
            format_job_state_label(record.state),
            format_job_kind_label(record.kind),
            record.priority,
            clip_text(&record.name, 64),
        );
        if let Some(reason) = record.failure_reason.as_ref() {
            line.push_str(&format!(" | reason={}", clip_text(reason, 48)));
        }
        lines.push(line);
        if lines.len() >= limit {
            break;
        }
    }

    if lines.is_empty() {
        return format!(
            "No jobs match filter '{}'. filters: all, queued, running, completed, failed, cancelled, terminal, image, video, agent, llm, code, system",
            normalized_filter
        );
    }
    lines.join("\n")
}

fn format_job_kind_label(kind: JobKind) -> &'static str {
    match kind {
        JobKind::CodeBuild => "code",
        JobKind::LlmInference => "llm",
        JobKind::ImageGeneration => "image",
        JobKind::VideoGeneration => "video",
        JobKind::AgentRun => "agent",
        JobKind::SystemTask => "system",
    }
}

fn format_job_state_label(state: JobState) -> &'static str {
    match state {
        JobState::Queued => "queued",
        JobState::Running => "running",
        JobState::Completed => "completed",
        JobState::Failed => "failed",
        JobState::Cancelled => "cancelled",
    }
}

fn job_record_matches_filter(record: &JobRecord, normalized_filter: &str) -> bool {
    match normalized_filter {
        "all" => true,
        "queued" => matches!(record.state, JobState::Queued),
        "running" => matches!(record.state, JobState::Running),
        "completed" => matches!(record.state, JobState::Completed),
        "failed" => matches!(record.state, JobState::Failed),
        "cancelled" => matches!(record.state, JobState::Cancelled),
        "terminal" => record.is_terminal(),
        "image" => matches!(record.kind, JobKind::ImageGeneration),
        "video" => matches!(record.kind, JobKind::VideoGeneration),
        "agent" => matches!(record.kind, JobKind::AgentRun),
        "llm" | "inference" => matches!(record.kind, JobKind::LlmInference),
        "code" | "build" => matches!(record.kind, JobKind::CodeBuild),
        "system" => matches!(record.kind, JobKind::SystemTask),
        _ => true,
    }
}
