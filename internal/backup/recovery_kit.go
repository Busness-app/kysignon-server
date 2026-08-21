package backup

import (
	"encoding/hex"
	"fmt"
	"html"
	"time"
)

// GenerateCustodianCardHTML renders the document handed to exactly one custodian. It carries
// that custodian's single shard and nothing else secret.
//
// Rendering every shard into one document collapsed the advertised 2-of-3 custody model to
// 1-of-1: whoever picked up that one file — from Downloads, a mail thread, an endpoint
// backup, a printer spool — held the whole reconstruction quorum. One shard per artifact is
// the property the model actually needs.
func GenerateCustodianCardHTML(manifest Manifest, share Share, appName, recoveryURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>%s Custodian Shard #%d - %s</title>
<style>%s</style>
</head>
<body>
<div class="container">
  <h1>Custodian Key Shard #%d</h1>
  <span class="badge">CONFIDENTIAL &bull; ONE CUSTODIAN ONLY</span>

  <div class="warn">
    <strong>Do not combine this document with other custodians' shards.</strong>
    Storing %d or more shards in one place removes the protection this scheme provides. This
    document is useless on its own and that is deliberate.
  </div>

  <div class="section">
    <h3>Your Shard</h3>
    <div class="share-card">
      <h4>Shard #%d of %d &bull; quorum %d</h4>
      <code>%s</code>
    </div>
  </div>

  <div class="section">
    <h3>Which Backup This Unlocks</h3>
    <table>
      <tr><th>Application</th><td>%s (v%s)</td></tr>
      <tr><th>Capsule ID</th><td><code>%s</code></td></tr>
      <tr><th>Created At</th><td>%s</td></tr>
      <tr><th>Payload Hash (SHA-256)</th><td><code>%s</code></td></tr>
      <tr><th>Origin</th><td><code>%s</code></td></tr>
    </table>
    <p class="muted">The encrypted <code>%s.kycap</code> container is a separate file held by
    the operator. Your shard cannot decrypt anything without it.</p>
  </div>

  <div class="section">
    <h3>Emergency Restore Procedure</h3>
    <ol>
      <li>The operator produces the <code>%s.kycap</code> container.</li>
      <li>At least <strong>%d</strong> custodians each supply their own shard document.</li>
      <li>Run the offline extractor shipped with KySignOn:
        <br><code>kyrestore -capsule %s.kycap -shard 1:&lt;hex&gt; -shard 2:&lt;hex&gt; -out ./restored</code></li>
      <li>The extractor recombines the shards over GF(256), decrypts the payload with
        AES-256-GCM, and refuses to write anything unless the SHA-256 payload hash matches
        <code>%s</code>.</li>
      <li>Copy the restored <code>data/</code> and <code>config/</code> trees into the
        production directory and start the service.</li>
    </ol>
  </div>
</div>
</body>
</html>`,
		html.EscapeString(appName), share.Index, html.EscapeString(manifest.CapsuleID),
		kitCSS,
		share.Index,
		manifest.Threshold,
		share.Index, manifest.TotalShares, manifest.Threshold,
		hex.EncodeToString(share.Data),
		html.EscapeString(appName), html.EscapeString(manifest.AppVersion),
		html.EscapeString(manifest.CapsuleID),
		manifest.CreatedAt.Format(time.RFC3339),
		html.EscapeString(manifest.PayloadHash),
		html.EscapeString(recoveryURL),
		html.EscapeString(manifest.CapsuleID),
		html.EscapeString(manifest.CapsuleID),
		manifest.Threshold,
		html.EscapeString(manifest.CapsuleID),
		html.EscapeString(manifest.PayloadHash),
	)
}

const kitCSS = `
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d0f14; color: #e2e8f0; margin: 0; padding: 40px 20px; }
  .container { max-width: 800px; margin: 0 auto; background: #161a22; border: 1px solid #1e293b; border-radius: 8px; padding: 32px; }
  h1 { color: #4deeea; margin-top: 0; }
  .badge { display: inline-block; background: #0e4a48; color: #4deeea; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
  .warn { margin-top: 20px; background: #2a1414; border: 1px solid #7f1d1d; border-radius: 6px; padding: 12px 16px; color: #fca5a5; font-size: 14px; line-height: 1.5; }
  .section { margin-top: 24px; border-top: 1px solid #1e293b; padding-top: 16px; }
  code { background: #0d0f14; padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, monospace; color: #4deeea; word-break: break-all; }
  .share-card { background: #0d0f14; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; margin-bottom: 12px; }
  .share-card h4 { margin: 0 0 8px; color: #64748b; }
  .muted { color: #64748b; font-size: 14px; }
  ol { line-height: 1.7; color: #cbd5e1; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid #1e293b; }
  th { color: #64748b; font-size: 13px; }
`
