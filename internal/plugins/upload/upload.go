package upload

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/evoscanner/evoscanner/internal/scanner"
	"github.com/evoscanner/evoscanner/pkg/types"
)

type Plugin struct{}

func (p *Plugin) ID() string { return "file-upload" }

func (p *Plugin) Name() string { return "File Upload/Download Detection" }

func (p *Plugin) Description() string {
	return "Detects file upload forms and file download endpoints for manual testing"
}

func (p *Plugin) Category() string { return "files" }

func (p *Plugin) Severity() types.Severity { return types.SeverityMedium }

func (p *Plugin) Compliance() []types.ComplianceRef {
	return nil
}

func (p *Plugin) Check(ctx context.Context, target *types.Target, endpoint *types.Endpoint, client scanner.HttpClient) ([]types.Finding, error) {
	if target == nil || endpoint == nil {
		return nil, nil
	}

	baseURL := strings.TrimSpace(endpoint.URL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(target.BaseURL)
	}
	if baseURL == "" {
		return nil, nil
	}

	findings := make([]types.Finding, 0)
	urlLower := strings.ToLower(baseURL)

	uploadIndicators := []string{
		"/upload",
		"/upload/",
		"/file-upload",
		"/file-upload/",
		"/uploadfile",
		"/upload.php",
		"/upload.jsp",
		"/upload.html",
		"/file",
		"/file/",
		"/files",
		"/files/",
		"/attach",
		"/attach/",
		"/attachment",
		"/attachment/",
		"/media",
		"/media/",
		"/image",
		"/image/",
		"/photo",
		"/photo/",
		"/avatar",
		"/avatar/",
		"/profile",
		"/profile/upload",
		"/upload/image",
		"/upload/photo",
		"/upload/file",
		"/admin/upload",
		"/cms/upload",
		"/board/upload",
		"/forum/upload",
		"/blog/upload",
		"/user/upload",
		"/member/upload",
		"/document/upload",
		"/doc/upload",
		"/pdf/upload",
		"/excel/upload",
		"/word/upload",
		"/ppt/upload",
		"/csv/upload",
		"/zip/upload",
		"/rar/upload",
		"/archive/upload",
		"/uploadify",
		"/plupload",
		"/fineuploader",
		"/jquery-upload",
		"/ajaxupload",
		"/dropzone",
		"/fileinput",
		"/upload-progress",
		"/proxy/upload",
		"/api/upload",
		"/rest/upload",
		"/v1/upload",
		"/v2/upload",
		"/content/upload",
		"/asset/upload",
		"/resource/upload",
		"/storage/upload",
		"/cloud/upload",
	}

	downloadIndicators := []string{
		"/download",
		"/download/",
		"/file/download",
		"/files/download",
		"/download.php",
		"/download.jsp",
		"/download.html",
		"/getfile",
		"/getfile/",
		"/readfile",
		"/readfile/",
		"/viewfile",
		"/viewfile/",
		"/export",
		"/export/",
		"/export.php",
		"/export.jsp",
		"/export/data",
		"/export/csv",
		"/export/excel",
		"/dump",
		"/dump/",
		"/backup",
		"/backup/",
		"/backup.php",
		"/backup.zip",
		"/backup.rar",
		"/database",
		"/database/",
		"/db",
		"/db/",
		"/sql",
		"/sql/",
		"/dump.sql",
		"/database.sql",
		"/wp-content",
		"/wp-includes",
		"/administrator",
		"/admin/file",
		"/admin/download",
		"/api/download",
		"/download/file",
		"/download/id/",
		"/download?name=",
		"/download?file=",
		"/download?id=",
		"/download?path=",
		"/file?",
		"/files?",
		"/download?",
		"/get?file=",
		"/get?path=",
		"/view?file=",
		"/view?path=",
		"/preview?file=",
		"/preview?path=",
		"/load?file=",
		"/load?path=",
		"/render?file=",
		"/render?path=",
		"/display?file=",
		"/display?path=",
	}

	isUpload := false
	for _, indicator := range uploadIndicators {
		if strings.Contains(urlLower, indicator) {
			isUpload = true
			break
		}
	}

	isDownload := false
	if !isUpload {
		for _, indicator := range downloadIndicators {
			if strings.Contains(urlLower, indicator) {
				isDownload = true
				break
			}
		}
	}

	if isUpload || isDownload {
		findingType := "File Upload Form"
		confidence := 0.6
		if isDownload {
			findingType = "File Download Endpoint"
			confidence = 0.5
		}

		findings = append(findings, types.Finding{
			ID:          fmt.Sprintf("%s-%d", p.ID(), time.Now().UnixNano()),
			PluginID:    p.ID(),
			Name:        findingType,
			Description: fmt.Sprintf("Potential %s detected. Manual testing recommended.", findingType),
			Severity:    p.Severity(),
			Confidence:  confidence,
			URL:         baseURL,
			Method:      endpoint.Method,
			Evidence:    "URL pattern matches known upload/download indicators",
			CWE:         []string{"CWE-434"},
			Remediation: "Verify file type restrictions, implement proper validation, and ensure secure storage",
			Timestamp:   time.Now(),
		})
	}

	return findings, nil
}
