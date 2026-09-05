import { useEffect, useState } from 'react';
import { apiJson, apiRequest, errorMessage } from '../api';
import { parseEnrollmentPolicies, parseEnrollmentPreview } from '../parsers';
import type { EnrollmentPolicy, EnrollmentPreview } from '../types';
import { isCancelled, useStepUp } from './StepUpPrompt';

export function AdminEnrollmentPolicies() {
 const [policies,setPolicies]=useState<EnrollmentPolicy[]>([]);
 const [draft,setDraft]=useState<EnrollmentPolicy|null>(null);
 const [preview,setPreview]=useState<EnrollmentPreview|null>(null);
 const [error,setError]=useState<string|null>(null);
 const [busy,setBusy]=useState(false);
 const {requestGrant,stepUpPrompt}=useStepUp();
 const reload=async()=>{try{setPolicies(await apiJson('/api/admin/enrollment-policies',parseEnrollmentPolicies));}catch(err){setError(errorMessage(err,'Could not load policies'));}};
 useEffect(()=>{void reload();},[]);
 const change=(p:EnrollmentPolicy)=>{setDraft(p);setPreview(null);setError(null);};
 const inspect=async(event:React.FormEvent)=>{
  event.preventDefault();if(!draft)return;setBusy(true);setError(null);
  try{setPreview(await apiJson('/api/admin/enrollment-policies/preview',parseEnrollmentPreview,{method:'POST',body:JSON.stringify(draft)}));}
  catch(err){setError(errorMessage(err,'Could not preview policy'));}finally{setBusy(false);}
 };
 const apply=async()=>{
  if(!draft||!preview?.canActivate)return;setBusy(true);setError(null);
  try{const path='/api/admin/enrollment-policies';const stepUpToken=await requestGrant(`Apply ${draft.scope} MFA policy. Outstanding OAuth sign-ins and registered tokens will be revoked. Existing deadlines are never extended.`,`PUT ${path}`);
   await apiRequest(path,{method:'PUT',stepUpToken,body:JSON.stringify(draft)});setDraft(null);setPreview(null);await reload();
  }catch(err){if(!isCancelled(err))setError(errorMessage(err,'Could not apply policy; reload before retrying.'));}finally{setBusy(false);}
 };
 return <div className="admin-page"><div className="page-header"><h1 className="page-title">MFA enrollment policies</h1><button className="secondary-btn" disabled={busy} onClick={()=>{setDraft(null);setPreview(null);void reload();}}>Reload policies</button></div>
  <p>Organization and administrator requirements combine: permitted factors must overlap, and the earliest enrollment deadline applies. App-specific authentication can remain stricter during grace.</p>
  <p>Before enabling a requirement, sign in as an administrator with a permitted factor within the last five minutes. This verifies a local administrator can still sign in; there is no policy bypass.</p>
  {error&&<div className="alert-box error" role="alert">{error}</div>}
  <div className="table-card"><table className="admin-table"><thead><tr><th>Scope</th><th>Requirement</th><th>Permitted factors</th><th>Grace</th><th>Action</th></tr></thead><tbody>{policies.map(p=><tr key={p.scope}><td>{p.scope==='organization'?'Everyone':'Administrators'}</td><td>{p.required?'MFA required':'No additional requirement'}</td><td>{p.allowedMethods.map(m=>m==='webauthn'?'Passkey':m.toUpperCase()).join(', ')}</td><td>{p.graceSeconds/86400} days</td><td><button className="secondary-btn" disabled={busy} onClick={()=>change(p)}>Edit {p.scope}</button></td></tr>)}</tbody></table></div>
  {draft&&<form className="settings-section" onSubmit={inspect}><div className="modal-body"><h2>{draft.scope==='organization'?'Organization':'Administrator'} policy</h2>
   <div className="form-group"><label><input type="checkbox" checked={draft.required} disabled={busy} onChange={e=>change({...draft,required:e.target.checked})}/> Require MFA</label></div>
   <fieldset disabled={busy}><legend>Permitted factors</legend>{(['totp','push','webauthn']).map(method=><label key={method} style={{display:'block',marginBottom:'0.5rem'}}><input type="checkbox" checked={draft.allowedMethods.includes(method)} onChange={e=>change({...draft,allowedMethods:e.target.checked?[...draft.allowedMethods,method]:draft.allowedMethods.filter(m=>m!==method)})}/> {method==='webauthn'?'Passkey':method.toUpperCase()}</label>)}</fieldset>
   <div className="form-group"><label className="form-label" htmlFor="enrollment-grace">Grace period for first-time enrollment (days)</label><input id="enrollment-grace" className="form-input" type="number" min="0" max="90" step="1" required disabled={busy} value={draft.graceSeconds/86400} onChange={e=>change({...draft,graceSeconds:e.target.valueAsNumber*86400})}/></div>
   <p>Zero requires enrollment immediately. Existing deadlines only become earlier; sign-in, disabling/re-enabling a policy, and longer grace settings cannot restart grace. Already-enrolled users must sign in with a permitted factor.</p>
   <button className="secondary-btn" disabled={busy||draft.allowedMethods.length===0}>Preview impact</button>
   {preview&&<div role="status"><p>{preview.affected} active users are covered; {preview.missingFactor} lack a permitted factor. {preview.restrictedSessions} live sessions would be restricted to enrollment. These counts include both policies.</p>
    {!preview.canActivate&&<p>Sign out and sign in with a permitted administrator factor, then reopen this policy. Password-only or recovery sign-in cannot activate it.</p>}
    <p>Applying cancels outstanding OAuth sign-ins and revokes registered tokens. Offline access tokens may remain valid for up to 15 minutes, and destination app sessions may last longer.</p>
    <button type="button" className="primary-btn" disabled={busy||!preview.canActivate} onClick={apply}>Apply policy</button>
   </div>}
  </div></form>}
  {stepUpPrompt}
 </div>;
}
