package api

import (
	"io/fs"
	"net/http"
)

// SetFrontend registers the embedded frontend to be served at /.
// The filesystem should be rooted at the build output directory
// (containing index.html, _app/, etc).
func (s *Server) SetFrontend(fsys fs.FS) {
	fileServer := http.FileServerFS(fsys)

	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// Try the exact path first; if the file doesn't exist,
		// serve index.html for SPA client-side routing.
		path := r.URL.Path
		if path != "/" {
			// Check if the file exists in the embedded FS
			f, err := fs.Stat(fsys, path[1:]) // strip leading /
			if err != nil || f.IsDir() {
				// SPA fallback — serve index.html
				r.URL.Path = "/"
			}
		}
		fileServer.ServeHTTP(w, r)
	})
}
