package backup

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenerateRecoveryKitHTML creates a self-contained, human-readable emergency disaster recovery document.
func GenerateRecoveryKitHTML(capsule *Capsule, appName, recoveryURL string) string {
	var sharesHTML strings.Builder
	for _, share := range capsule.Shares {
		sharesHTML.WriteString(fmt.Sprintf(`
		<div class="share-card">
			<h4>Custodian Key Shard #%d</h4>
			<code>%s</code>
		</div>`, share.Index, hex.EncodeToString(share.Data)))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KySecurity Disaster Recovery Kit - %s</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d0f14; color: #e2e8f0; margin: 0; padding: 40px 20px; }
  .container { max-width: 800px; margin: 0 auto; background: #161a22; border: 1px solid #1e293b; border-radius: 8px; padding: 32px; }
  h1 { color: #4deeea; margin-top: 0; }
  .badge { display: inline-block; background: #0e4a48; color: #4deeea; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
  .section { margin-top: 24px; border-top: 1px solid #1e293b; padding-top: 16px; }
  code { background: #0d0f14; padding: 2px 6px; border-radius: 4px; font-family: ui-monospace, monospace; color: #4deeea; word-break: break-all; }
  .share-card { background: #0d0f14; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; margin-bottom: 12px; }
  .share-card h4 { margin: 0 0 8px; color: #64748b; }
  table { width: 100%%; border-collapse: collapse; margin-top: 12px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid #1e293b; }
  th { color: #64748b; font-size: 13px; }
</style>
</head>
<body>
<div class="container">
  <h1>Disaster Recovery Kit</h1>
  <span class="badge">CONFIDENTIAL &bull; EMERGENCY USE ONLY</span>
  
  <div class="section">
    <h3>Service Metadata</h3>
    <table>
      <tr><th>Application</th><td>%s (v%s)</td></tr>
      <tr><th>Capsule ID</th><td><code>%s</code></td></tr>
      <tr><th>Created At</th><td>%s</td></tr>
      <tr><th>Payload Hash (SHA-256)</th><td><code>%s</code></td></tr>
      <tr><th>Threshold Quorum</th><td>%d of %d Custodians Required</td></tr>
    </table>
  </div>

  <div class="section">
    <h3>Shamir Key Shards</h3>
    <p style="color: #64748b; font-size: 14px;">Distribute each shard to separate designated custodians. Any %d shards can reconstruct the capsule master key.</p>
    %s
  </div>

  <div class="section">
    <h3>Emergency Restore Instructions</h3>
    <ol style="line-height: 1.6; color: #cbd5e1;">
      <li>Collect at least <strong>%d key shards</strong> from authorized custodians.</li>
      <li>Combine shards using Shamir Secret Sharing algorithm over GF(256).</li>
      <li>Decrypt the encrypted <code>.kycap</code> archive with AES-256-GCM using the reconstructed 256-bit key.</li>
      <li>Verify SHA-256 payload checksum matches <code>%s</code>.</li>
      <li>Extract archive into production directory and launch service.</li>
    </ol>
  </div>
</div>
</body>
</html>`,
		appName,
		appName,
		capsule.Manifest.AppVersion,
		capsule.Manifest.CapsuleID,
		capsule.Manifest.CreatedAt.Format(time.RFC3339),
		capsule.Manifest.PayloadHash,
		capsule.Manifest.Threshold,
		capsule.Manifest.TotalShares,
		capsule.Manifest.Threshold,
		sharesHTML.String(),
		capsule.Manifest.Threshold,
		capsule.Manifest.PayloadHash,
	)
}
