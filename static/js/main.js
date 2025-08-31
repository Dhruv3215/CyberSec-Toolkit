document.addEventListener("DOMContentLoaded", () => {
  const tabs = document.querySelectorAll(".tabbtn");
  const panels = document.querySelectorAll(".panel");
  const footerNotes = document.getElementById("footer_notes");

  // ======================
  // FOOTER NOTES PER TAB
  // ======================
  const tabNotes = {
    "analyze": [
      {title: "Method", body: "Entropy + zxcvbn checks. Crack time estimated by hash & hardware."},
      {title: "Checklist", body: "Upper · Lower · Digit · Special · Length thresholds · Common phrase detection."},
      {title: "Export", body: "Generate a PDF report with results & recommendations."}
    ],
    "generate": [
      {title: "Policy", body: "Supports NIST, PCI, or company password rules."},
      {title: "Batch", body: "Generate multiple unique passwords in one click."},
      {title: "Wordlist", body: "Export .txt wordlists for cracking tools."}
    ],
    "hash": [
      {title: "Sources", body: "Use pasted list, uploaded file, or last generated wordlist."},
      {title: "Salt", body: "Supports prefix/suffix salt for MD5/SHA-*."},
      {title: "Storage", body: "Results stored in SQLite for later lookup."}
    ],
    "history": [
      {title: "Audit", body: "Actions and crack attempts are logged in SQLite."},
      {title: "Security", body: "APIs can be protected with API keys and rate limits."}
    ]
  };

  function updateFooter(tab) {
    footerNotes.innerHTML = "";
    (tabNotes[tab] || []).forEach(note => {
      const div = document.createElement("div");
      div.className = "note-card";
      div.innerHTML = `<strong>${note.title}</strong><br>${note.body}`;
      footerNotes.appendChild(div);
    });
  }

  tabs.forEach(btn => {
    btn.addEventListener("click", () => {
      tabs.forEach(b => b.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.tab).classList.add("active");
      updateFooter(btn.dataset.tab);
    });
  });

  // Initialize footer with default tab
  updateFooter("analyze");

  // ======================
  // SHOW / HIDE PASSWORD
  // ======================
  const pwInput = document.getElementById("pw_input");
  const eyeBtn = document.getElementById("toggle_eye");

  if (pwInput && eyeBtn) {
    eyeBtn.addEventListener("click", () => {
      if (pwInput.type === "password") {
        pwInput.type = "text";
        eyeBtn.textContent = "🙈";
      } else {
        pwInput.type = "password";
        eyeBtn.textContent = "👁️";
      }
    });
  }
  // Show/Hide toggle for Hash tab
  const hashInput = document.getElementById("hash_value");
  const hashEyeBtn = document.getElementById("toggle_hash_eye");

  if (hashInput && hashEyeBtn) {
    hashEyeBtn.addEventListener("click", () => {
      if (hashInput.type === "password") {
        hashInput.type = "text";
        hashEyeBtn.textContent = "🙈";
      } else {
        hashInput.type = "password";
        hashEyeBtn.textContent = "👁️";
      }
    });
  }
  function updateChecklist(data) {
    toggleCheck("ck_upper", data.checklist.has_upper);
    toggleCheck("ck_lower", data.checklist.has_lower);
    toggleCheck("ck_digit", data.checklist.has_digit);
    toggleCheck("ck_special", data.checklist.has_special);
    toggleCheck("ck_len8", data.checklist.len_ge_8);
    toggleCheck("ck_len12", data.checklist.len_ge_12);
  }

  function toggleCheck(id, state) {
    const el = document.getElementById(id);
    if (!el) return;
      const icon = el.querySelector(".icon");
    if (state) {
      el.classList.add("valid");
      icon.textContent = "✔";
    } else {
      el.classList.remove("valid");
      icon.textContent = "✖";
    }
  }

  // ======================
  // PASSWORD ANALYSIS
  // ======================
  const analyzeBtn = document.getElementById("analyze_btn");
  const copyBtn = document.getElementById("copy_btn");
  const reportBtn = document.getElementById("report_btn");

  if (analyzeBtn) {
    analyzeBtn.addEventListener("click", async () => {
      const pw = pwInput.value;
      if (!pw) return;

      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          password: pw,
          hash_algo: document.getElementById("an_hash").value,
          hardware: document.getElementById("an_hw").value
        })
      });
      const data = await res.json();

      document.getElementById("score").textContent = data.score;
      document.getElementById("entropy").textContent = data.entropy;
      document.getElementById("category").textContent = data.category;
      document.getElementById("zx_score").textContent = data.zxcvbn_score;
      document.getElementById("ttc").textContent = data.time_to_crack;
      document.getElementById("strength_fill").style.width = (data.score * 10) + "%";

      updateChecklist(data);

      document.getElementById("reco").innerHTML = data.recommendations.join("<br>");

      reportBtn.style.display = "inline-block";
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      if (pwInput.value) {
        navigator.clipboard.writeText(pwInput.value);
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
      }
    });
  }

    if (reportBtn) {
    reportBtn.addEventListener("click", async () => {
      const pw = pwInput.value;
      if (!pw) return;

      try {
        const res = await fetch("/api/report/create", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
          body: JSON.stringify({
            password: pw,
            policy: document.getElementById("policy_select")?.value || "default",
            algorithm: document.getElementById("an_hash").value || "sha256"
          })
        });

        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          alert("❌ Failed to generate report. " + (err.error || ""));
          return;
        }

        const { url } = await res.json();
        if (url) {
          // 👉 redirect user to HTML report page
          window.location.href = url;
        } else {
          alert("❌ Report generation failed: no URL returned.");
        }
      } catch (e) {
        alert("❌ Network error while generating report.");
      }
    });
  }

  // ======================
  // PASSWORD GENERATION
  // ======================
  const genPassBtn = document.getElementById("gen_pass");
  const genListBtn = document.getElementById("gen_list");
  const downloadListBtn = document.getElementById("download_list");

  if (genPassBtn) {
    genPassBtn.addEventListener("click", async () => {
      const inputs = {
        name: document.getElementById("g_name").value,
        pet: document.getElementById("g_pet").value,
        hobbies: document.getElementById("g_hobby").value,
        crush: document.getElementById("g_crush").value,
        dob: document.getElementById("g_dob").value,
        random: document.getElementById("g_random").value
      };
      const res = await fetch("/api/generate", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-API-Key": API_KEY},
        body: JSON.stringify({
          mode: "password",
          inputs,
          min_len: document.getElementById("g_min").value,
          max_len: document.getElementById("g_max").value,
          count: document.getElementById("g_count").value,
          method: document.getElementById("method_pass").value,
          policy: document.getElementById("policy").value
        })
      });
      const data = await res.json();
      document.getElementById("gen_pwd_preview").textContent = (data.passwords || []).join("\n");
    });
  }

  if (genListBtn) {
    genListBtn.addEventListener("click", async () => {
      const inputs = {
        name: document.getElementById("g_name").value,
        pet: document.getElementById("g_pet").value,
        hobbies: document.getElementById("g_hobby").value,
        crush: document.getElementById("g_crush").value,
        dob: document.getElementById("g_dob").value,
        random: document.getElementById("g_random").value
      };

      const res = await fetch("/api/generate_stream", {   // ✅ streaming endpoint
        method: "POST",
        headers: {"Content-Type": "application/json", "X-API-Key": API_KEY},
        body: JSON.stringify({
          mode: "wordlist",
          inputs,
          min_len: document.getElementById("g_min").value,
          max_len: document.getElementById("g_max").value,
          limit: document.getElementById("g_limit").value,
          method: document.getElementById("method_list").value,
          policy: document.getElementById("policy").value
        })
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const lines = decoder.decode(value).trim().split("\n");
        for (let line of lines) {
          if (!line) continue;
          const msg = JSON.parse(line);

          if (msg.type === "progress" && msg.pct !== undefined) {
            document.getElementById("gen_progress_wrap").style.display = "block";
            document.getElementById("gen_progress").style.width = msg.pct + "%";
          }

          if (msg.type === "done" && msg.mode === "wordlist") {
            downloadListBtn.style.display = "inline-block";
            downloadListBtn.onclick = () => {
              window.location.href = "/api/download/" + msg.file_id;
            };

            // Hide progress after short delay
            setTimeout(() => {
              document.getElementById("gen_progress_wrap").style.display = "none";
              document.getElementById("gen_progress").style.width = "0%";
            }, 1500);
          }
        }
      }
    });
  }

  // ======================
  // HASH CRACKER - FILE UPLOAD
  // ======================
  const dropZone = document.getElementById("drop_zone");
  const fileInput = document.getElementById("file_input");
  const uploadStatus = document.getElementById("upload_status");

  const MAX_SIZE = 5 * 1024 * 1024; // 5 MB
  let uploadedFileId = null; // store backend file_id after upload

  if (dropZone && fileInput) {
    // Prevent default drag behaviors
    ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
      dropZone.addEventListener(eventName, e => e.preventDefault(), false);
      document.body.addEventListener(eventName, e => e.preventDefault(), false);
    });

    // Highlight on dragover
    dropZone.addEventListener("dragover", () => dropZone.classList.add("highlight"));
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("highlight"));
    dropZone.addEventListener("drop", e => {
      dropZone.classList.remove("highlight");
      if (e.dataTransfer.files.length) {
        const file = e.dataTransfer.files[0];
        handleFileUpload(file);
      }
    });

    // When selecting with Browse
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) {
        const file = fileInput.files[0];
        handleFileUpload(file);
      }
    });
  }

  // Handle validation + upload
  function handleFileUpload(file) {
    if (!uploadStatus) return;

    // ✅ Size validation (client-side)
    if (file.size > MAX_SIZE) {
      uploadStatus.textContent = "❌ File too large (max 5 MB)";
      uploadStatus.style.color = "red";
      fileInput.value = ""; // reset
      uploadedFileId = null;
      return;
    }

    uploadStatus.textContent = `Uploading ${file.name}...`;
    uploadStatus.style.color = "orange";

    const formData = new FormData();
    formData.append("file", file);

    fetch("/api/upload_wordlist", {
      method: "POST",
      headers: { "X-API-Key": API_KEY },
      body: formData
    })
    .then(r => r.json())
    .then(res => {
      if (res.error) {
        uploadStatus.textContent = "❌ " + res.error;
        uploadStatus.style.color = "red";
        uploadedFileId = null;
      } else {
        uploadedFileId = res.file_id;
        uploadStatus.textContent = "✅ Uploaded: " + res.filename;
        uploadStatus.style.color = "limegreen";
      }
    })
    .catch(err => {
      uploadStatus.textContent = "❌ Upload failed";
      uploadStatus.style.color = "red";
      uploadedFileId = null;
    });
  }

  // ======================
  // HASH CRACKING
  // ======================
  const crackBtn = document.getElementById("crack_stream_btn");

  if (crackBtn) {
    crackBtn.addEventListener("click", async () => {
      const algo = document.getElementById("hash_algo").value;
      const hash = document.getElementById("hash_value").value;
      const salt = document.getElementById("salt_value").value;
      const saltPos = document.getElementById("salt_pos").value;
      const wordlistPaste = document.getElementById("wordlist_paste").value.trim().split("\n").filter(Boolean);

      let bodyData = {
        algorithm: algo,
        hash,
        salt,
        salt_pos: saltPos
      };

      // ✅ If user uploaded a file, use file_id
      if (uploadedFileId) {
        bodyData.file_id = uploadedFileId;
      } else if (wordlistPaste.length > 0) {
        // Else fallback to pasted list
        bodyData.wordlist = wordlistPaste;
      } else {
        document.getElementById("crack_result").textContent = "❌ No wordlist uploaded or pasted";
        return;
      }

      // --- Start cracking request ---
      const res = await fetch("/api/crack_stream", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-API-Key": API_KEY},
        body: JSON.stringify(bodyData)
      });

      if (!res.ok) {
        document.getElementById("crack_result").textContent = "❌ Crack request failed";
        return;
      }

      // --- Streaming response ---
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let resultBox = document.getElementById("crack_result");
      let progressFill = document.getElementById("crack_progress");

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const lines = decoder.decode(value).trim().split("\n");
        for (let line of lines) {
          if (!line) continue;
          const msg = JSON.parse(line);

          if (msg.type === "progress") {
            let pct = msg.pct;
            if (pct === undefined && msg.done && msg.total) {
              pct = Math.floor((msg.done / msg.total) * 100);
            }
            progressFill.style.width = msg.pct + "%";
          } else if (msg.type === "done") {
            resultBox.textContent = msg.found
              ? "✅ Password found: " + msg.password
              : "❌ Not found";

            // ✅ Only clear status/progress if last upload was valid
            if (uploadedFileId) {
              setTimeout(() => {
                uploadStatus.textContent = "";
                uploadStatus.style.color = "";
                progressFill.style.width = "0%";
              }, 3000);
            } else {
              // Keep error message visible if upload failed
              progressFill.style.width = "0%";
            }
          }
        }
      }
    });
  }


  // ======================
  // HISTORY
  // ======================
  async function loadHistory() {
    const res = await fetch("/api/history");
    const data = await res.json();
    const list = document.getElementById("history_list");
    list.innerHTML = "";

    if (data.length === 0) {
      list.innerHTML = "<div class='history-empty'>No history yet.</div>";
      return;
    }

    data.forEach(ev => {
      const div = document.createElement("div");
      div.className = "history-item";
      div.textContent = `[${ev.time}] ${ev.action} - ${ev.detail}`;
      list.appendChild(div);
    });
  }

  // Attach "Clear History" button handler
  const clearBtn = document.getElementById("clear_history_btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      if (!confirm("Are you sure you want to clear history?")) return;
      const res = await fetch("/api/history/clear", {
        method: "POST",
        headers: {"X-API-Key": API_KEY}
      });
      if (res.ok) {
        document.getElementById("history_list").innerHTML =
          "<div class='history-empty'>History cleared.</div>";
      }
    });
  }

  // Load history when tab opens
  document.querySelector("[data-tab='history']").addEventListener("click", loadHistory);
});
