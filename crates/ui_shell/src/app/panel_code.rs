#[allow(clippy::too_many_arguments)]
fn code_studio_panel(
    workspace: Rc<WorkspaceHost>,
    queue: Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
    code_file_list: RwSignal<String>,
    code_editor_path: RwSignal<String>,
    code_editor_preview: RwSignal<String>,
    code_editor_append: RwSignal<String>,
    code_search_query: RwSignal<String>,
    code_search_results: RwSignal<String>,
    code_git_summary: RwSignal<String>,
    code_terminal_command: RwSignal<String>,
    code_terminal_output: RwSignal<String>,
    terminal_sessions: Rc<RefCell<TerminalSessionManager>>,
    code_terminal_session_id: RwSignal<Option<u64>>,
    code_terminal_session_state: RwSignal<String>,
    code_terminal_stream_output: RwSignal<String>,
    code_terminal_stdin: RwSignal<String>,
    code_queue_status: RwSignal<String>,
) -> impl IntoView {
    let refresh_files = {
        let workspace = workspace.clone();
        let queue = queue.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "code-refresh-files".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            match workspace.list_files(60) {
                Ok(files) => {
                    code_file_list.set(format_file_list(&files));
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status
                        .set(format!("files refreshed [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_file_list.set(format!("Workspace files error: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("workspace list failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "files refresh failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let load_editor_file = {
        let workspace = workspace.clone();
        let queue = queue.clone();
        move || {
            let path = code_editor_path.get();
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-load-{path}"),
                JobKind::CodeBuild,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            match workspace.read_file_excerpt(&path, 80, 5000) {
                Ok(excerpt) => {
                    code_editor_preview.set(excerpt);
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!("editor loaded [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_editor_preview.set(format!("Editor open failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("editor load failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "editor load failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let append_editor_line = {
        let workspace = workspace.clone();
        let queue = queue.clone();
        move || {
            let path = code_editor_path.get();
            let line = code_editor_append.get();
            if line.trim().is_empty() {
                code_editor_preview.set(String::from("append line is empty"));
                code_queue_status.set(String::from("append skipped: line is empty"));
                return;
            }
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-append-{path}"),
                JobKind::CodeBuild,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            let current = match workspace.read_file(&path) {
                Ok(content) => content,
                Err(error) => {
                    code_editor_preview.set(format!("editor read failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("editor read failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!("append failed [job #{}]", tracked_job_id.raw()));
                    persist_job_queue_with_notice(&queue, code_queue_status);
                    return;
                }
            };
            let mut updated = current;
            if !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push_str(&line);
            updated.push('\n');
            match workspace.write_file(&path, &updated) {
                Ok(()) => match workspace.read_file_excerpt(&path, 80, 5000) {
                    Ok(excerpt) => {
                        code_editor_preview.set(excerpt);
                        let _ = queue_complete_tracked_job(
                            &queue,
                            tracked_job_id,
                            queued_jobs,
                            running_jobs,
                            completed_jobs,
                            failed_jobs,
                            cancelled_jobs,
                        );
                        code_queue_status
                            .set(format!("append saved [job #{}]", tracked_job_id.raw()));
                    }
                    Err(error) => {
                        code_editor_preview.set(format!("editor refresh failed: {error:?}"));
                        let _ = queue_fail_tracked_job(
                            &queue,
                            tracked_job_id,
                            format!("editor refresh failed: {error:?}"),
                            queued_jobs,
                            running_jobs,
                            completed_jobs,
                            failed_jobs,
                            cancelled_jobs,
                        );
                        code_queue_status.set(format!(
                            "append refresh failed [job #{}]",
                            tracked_job_id.raw()
                        ));
                    }
                },
                Err(error) => {
                    code_editor_preview.set(format!("editor save failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("editor save failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "append save failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let run_search = {
        let workspace = workspace.clone();
        let queue = queue.clone();
        move || {
            let query = code_search_query.get();
            if query.trim().is_empty() {
                code_search_results.set(String::from("Search query is empty"));
                code_queue_status.set(String::from("search skipped: query is empty"));
                return;
            }
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-search-{}", clip_text(&query, 40)),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            match workspace.search(&query, 20) {
                Ok(hits) => {
                    let mut output = format!("Search '{query}' ({} hits)\n", hits.len());
                    for hit in hits {
                        output.push_str(&format!(
                            "- {}:{} | {}\n",
                            hit.path, hit.line_number, hit.line_excerpt
                        ));
                    }
                    code_search_results.set(output.trim_end().to_string());
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status
                        .set(format!("search complete [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_search_results.set(format!("Search failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("search failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!("search failed [job #{}]", tracked_job_id.raw()));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let refresh_git = {
        let workspace = workspace.clone();
        let queue = queue.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "code-git-status".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            match workspace.git_status() {
                Ok(summary) => {
                    code_git_summary.set(format_git_summary(&summary));
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "git refresh complete [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
                Err(error) => {
                    code_git_summary.set(format!("Git summary unavailable: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("git status failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "git refresh failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let start_stream = {
        let terminal_sessions = terminal_sessions.clone();
        let queue = queue.clone();
        move || {
            let command = code_terminal_command.get();
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-stream-start-{}", clip_text(&command, 40)),
                JobKind::CodeBuild,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            let mut sessions = terminal_sessions.borrow_mut();
            match sessions.start_session(&command) {
                Ok(session_id) => {
                    code_terminal_session_id.set(Some(session_id.raw()));
                    code_terminal_session_state.set(String::from("running"));
                    code_terminal_stream_output
                        .set(format!("session {} started\n", session_id.raw()));
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status
                        .set(format!("stream started [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_terminal_session_state.set(format!("start failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("stream start failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "stream start failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let poll_stream = {
        let terminal_sessions = terminal_sessions.clone();
        let queue = queue.clone();
        move || {
            let Some(raw_id) = code_terminal_session_id.get() else {
                code_terminal_session_state.set(String::from("no active session"));
                code_queue_status.set(String::from("poll skipped: no active session"));
                return;
            };
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-stream-poll-{raw_id}"),
                JobKind::SystemTask,
                JobPriority::Background,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            let session_id = TerminalSessionId::from_raw(raw_id);
            let mut sessions = terminal_sessions.borrow_mut();
            match sessions.poll_output(session_id, 120) {
                Ok(poll) => {
                    if !poll.lines.is_empty() {
                        let mut output = code_terminal_stream_output.get();
                        output.push_str(&poll.lines.join("\n"));
                        output.push('\n');
                        code_terminal_stream_output.set(clip_text(&output, 8000));
                    }
                    if poll.dropped_since_last_poll > 0 {
                        let mut output = code_terminal_stream_output.get();
                        output.push_str(&format!(
                            "[output trimmed: {} line(s) dropped]\n",
                            poll.dropped_since_last_poll
                        ));
                        code_terminal_stream_output.set(clip_text(&output, 8000));
                    }
                }
                Err(error) => {
                    code_terminal_session_state.set(format!("poll failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("stream poll failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "stream poll failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                    persist_job_queue_with_notice(&queue, code_queue_status);
                    return;
                }
            }
            match sessions.status(session_id) {
                Ok(status) => {
                    code_terminal_session_state.set(format_terminal_session_state(&status.state));
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!("stream polled [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_terminal_session_state.set(format!("status failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("stream status failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "stream status failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let stop_stream = {
        let terminal_sessions = terminal_sessions.clone();
        let queue = queue.clone();
        move || {
            let Some(raw_id) = code_terminal_session_id.get() else {
                code_terminal_session_state.set(String::from("no active session"));
                code_queue_status.set(String::from("stop skipped: no active session"));
                return;
            };
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-stream-stop-{raw_id}"),
                JobKind::CodeBuild,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            let session_id = TerminalSessionId::from_raw(raw_id);
            let mut sessions = terminal_sessions.borrow_mut();
            match sessions.stop_session(session_id) {
                Ok(_) => {}
                Err(error) => {
                    code_terminal_session_state.set(format!("stop failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("stream stop failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "stream stop failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                    persist_job_queue_with_notice(&queue, code_queue_status);
                    return;
                }
            }
            match sessions.status(session_id) {
                Ok(status) => {
                    code_terminal_session_state.set(format_terminal_session_state(&status.state));
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status
                        .set(format!("stream stopped [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_terminal_session_state.set(format!("status failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("stream stop status failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "stream stop status failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let clear_stream = {
        let terminal_sessions = terminal_sessions.clone();
        let queue = queue.clone();
        move || {
            let Some(raw_id) = code_terminal_session_id.get() else {
                code_terminal_session_state.set(String::from("no active session"));
                code_queue_status.set(String::from("clear skipped: no active session"));
                return;
            };
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-stream-clear-{raw_id}"),
                JobKind::SystemTask,
                JobPriority::Background,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            let session_id = TerminalSessionId::from_raw(raw_id);
            let mut sessions = terminal_sessions.borrow_mut();
            match sessions.clear_session(session_id) {
                Ok(_) => {
                    code_terminal_session_id.set(None);
                    code_terminal_session_state.set(String::from("cleared"));
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status
                        .set(format!("stream cleared [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_terminal_session_state.set(format!("clear failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("stream clear failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "stream clear failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let run_terminal_once = {
        let queue = queue.clone();
        move || {
            let command = code_terminal_command.get();
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-terminal-once-{}", clip_text(&command, 40)),
                JobKind::CodeBuild,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);
            match workspace.run_terminal_command(&command) {
                Ok(result) => {
                    code_terminal_output.set(format_terminal_output(&result));
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "terminal command complete [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
                Err(error) => {
                    code_terminal_output.set(format!("terminal error: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("terminal command failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "terminal command failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };

    let send_stream_input = {
        let terminal_sessions = terminal_sessions.clone();
        let queue = queue.clone();
        move || {
            let Some(raw_id) = code_terminal_session_id.get() else {
                code_terminal_session_state.set(String::from("no active session"));
                code_queue_status.set(String::from("input skipped: no active session"));
                return;
            };
            let mut payload = code_terminal_stdin.get();
            if payload.trim().is_empty() {
                code_terminal_session_state.set(String::from("input is empty"));
                code_queue_status.set(String::from("input skipped: empty payload"));
                return;
            }
            if !payload.ends_with('\n') {
                payload.push('\n');
            }
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("code-stream-input-{raw_id}"),
                JobKind::SystemTask,
                JobPriority::Background,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, code_queue_status);

            let session_id = TerminalSessionId::from_raw(raw_id);
            let mut sessions = terminal_sessions.borrow_mut();
            match sessions.send_input(session_id, &payload) {
                Ok(bytes) => {
                    let mut output = code_terminal_stream_output.get();
                    output.push_str(&format!("stdin> {}\n", payload.trim_end()));
                    code_terminal_stream_output.set(clip_text(&output, 8000));
                    code_terminal_session_state.set(format!("input sent ({bytes} byte(s))"));
                    code_terminal_stdin.set(String::new());
                    let _ = queue_complete_tracked_job(
                        &queue,
                        tracked_job_id,
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status
                        .set(format!("stream input sent [job #{}]", tracked_job_id.raw()));
                }
                Err(error) => {
                    code_terminal_session_state.set(format!("input failed: {error:?}"));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("stream input failed: {error:?}"),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    code_queue_status.set(format!(
                        "stream input failed [job #{}]",
                        tracked_job_id.raw()
                    ));
                }
            }
            persist_job_queue_with_notice(&queue, code_queue_status);
        }
    };
    let refresh_files = guarded_ui_action("code.refresh_files", Some(code_queue_status), refresh_files);
    let load_editor_file =
        guarded_ui_action("code.load_editor_file", Some(code_queue_status), load_editor_file);
    let append_editor_line =
        guarded_ui_action("code.append_editor_line", Some(code_queue_status), append_editor_line);
    let run_search = guarded_ui_action("code.run_search", Some(code_queue_status), run_search);
    let refresh_git = guarded_ui_action("code.refresh_git", Some(code_queue_status), refresh_git);
    let run_terminal_once =
        guarded_ui_action("code.run_terminal_once", Some(code_queue_status), run_terminal_once);
    let start_stream = guarded_ui_action("code.start_stream", Some(code_queue_status), start_stream);
    let poll_stream = guarded_ui_action("code.poll_stream", Some(code_queue_status), poll_stream);
    let stop_stream = guarded_ui_action("code.stop_stream", Some(code_queue_status), stop_stream);
    let clear_stream =
        guarded_ui_action("code.clear_stream", Some(code_queue_status), clear_stream);
    let send_stream_input =
        guarded_ui_action("code.send_stream_input", Some(code_queue_status), send_stream_input);

    Stack::vertical((
        Label::derived(|| "Code Studio"),
        Stack::horizontal((
            Label::derived(|| "Editor"),
            TextInput::new(code_editor_path).style(|s| s.min_width(260.0).padding(6.0).color(theme::input_text())),
            Button::new("Load").action(load_editor_file),
            Button::new("Refresh Files").action(refresh_files),
        ))
        .style(|s| s.gap(8.0)),
        Stack::horizontal((
            Label::derived(|| "Append line"),
            TextInput::new(code_editor_append).style(|s| s.min_width(260.0).padding(6.0).color(theme::input_text())),
            Button::new("Append + Save").action(append_editor_line),
        ))
        .style(|s| s.gap(8.0)),
        Scroll::new(Label::derived(move || code_editor_preview.get())).style(|s| {
            s.width_full()
                .height(160.0)
                .padding(6.0)
                .background(theme::surface_1())
        }),
        Stack::horizontal((
            Label::derived(|| "Search"),
            TextInput::new(code_search_query).style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
            Button::new("Run Search").action(run_search),
            Button::new("Refresh Git").action(refresh_git),
        ))
        .style(|s| s.gap(8.0)),
        Scroll::new(Label::derived(move || code_search_results.get())).style(|s| {
            s.width_full()
                .height(100.0)
                .padding(6.0)
                .background(theme::surface_1())
        }),
        Stack::horizontal((
            Label::derived(|| "Terminal"),
            TextInput::new(code_terminal_command).style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
            Button::new("Run Once").action(run_terminal_once),
            Button::new("Start Stream").action(start_stream),
            Button::new("Poll Stream").action(poll_stream),
            Button::new("Stop Stream").action(stop_stream),
            Button::new("Clear Stream").action(clear_stream),
        ))
        .style(|s| s.gap(8.0)),
        Stack::horizontal((
            Label::derived(|| "Session Input"),
            TextInput::new(code_terminal_stdin).style(|s| s.min_width(260.0).padding(6.0).color(theme::input_text())),
            Button::new("Send Input").action(send_stream_input),
        ))
        .style(|s| s.gap(8.0)),
        Label::derived(move || format!("Terminal session: {}", code_terminal_session_state.get()))
            .style(|s| s.color(theme::text_secondary())),
        Label::derived(move || format!("Queue status: {}", code_queue_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        Scroll::new(Label::derived(move || code_git_summary.get())).style(|s| {
            s.width_full()
                .height(80.0)
                .padding(6.0)
                .background(theme::surface_1())
                .color(theme::text_secondary())
        }),
        Scroll::new(Label::derived(move || code_terminal_output.get())).style(|s| {
            s.width_full()
                .height(90.0)
                .padding(6.0)
                .background(theme::surface_1())
                .color(theme::text_secondary())
        }),
        Scroll::new(Label::derived(move || code_terminal_stream_output.get())).style(|s| {
            s.width_full()
                .height(120.0)
                .padding(6.0)
                .background(theme::surface_1())
                .color(theme::text_secondary())
        }),
        Scroll::new(Label::derived(move || code_file_list.get())).style(|s| {
            s.width_full()
                .height(110.0)
                .padding(6.0)
                .background(theme::surface_1())
        }),
    ))
    .style(|s| s.size_full().padding(12.0).row_gap(8.0))
}


