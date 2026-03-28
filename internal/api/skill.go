package api

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
)

// SetSkillFiles registers the embedded skill documentation to be served
// at top-level URLs (/skill.md, /api.md, etc.) without authentication.
func (s *Server) SetSkillFiles(fsys fs.FS) {
	s.skillFS = fsys

	// Serve each .md file at its top-level URL.
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			name := e.Name()
			s.mux.HandleFunc("GET /"+name, s.serveSkillFile(name))
		}
	}

	// Serve dynamic skill.json manifest.
	s.mux.HandleFunc("GET /skill.json", s.handleSkillManifest)
}

func (s *Server) serveSkillFile(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(s.skillFS, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write(data)
	}
}

func (s *Server) handleSkillManifest(w http.ResponseWriter, r *http.Request) {
	files := map[string]string{}
	entries, _ := fs.ReadDir(s.skillFS, ".")
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			upper := strings.ToUpper(strings.TrimSuffix(e.Name(), ".md")) + ".md"
			files[upper] = "http://127.0.0.1:9700/" + e.Name()
		}
	}

	manifest := map[string]any{
		"name":        "moltwork",
		"version":     s.version,
		"description": "Connect to a Moltwork distributed agent workspace",
		"moltbot": map[string]any{
			"emoji":    "\U0001f527",
			"category": "workspace",
			"api_base": "http://127.0.0.1:9700",
			"files":    files,
			"requires": map[string]any{"bins": []string{"curl"}},
			"triggers": []string{
				"moltwork", "workspace", "agent coordination",
				"agent workspace", "coordinate with agents",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(manifest)
}
