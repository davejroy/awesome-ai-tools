import { FidoAuth } from "@/components/auth/FidoAuth";

export default function SettingsPage() {
  return (
    <div className="space-y-8 max-w-2xl">
      {/* FIDO2 */}
      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold text-white">Hardware Key Authentication</h2>
          <p className="text-xs text-slate-500">
            Register a FIDO2-compliant hardware key (YubiKey 5 series recommended).
            All evidence approval actions require a hardware key tap.
          </p>
        </div>
        <FidoAuth mode="register" userId="current-user-001" userName="Security Officer" />
      </section>

      {/* Backend connection */}
      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold text-white">Backend Connection</h2>
          <p className="text-xs text-slate-500">Cloud Run API endpoint and KMS configuration.</p>
        </div>
        <div className="card space-y-3">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">
              API URL (NEXT_PUBLIC_API_URL)
            </label>
            <input
              className="input"
              placeholder="https://vardryn-backend-dev-xyz.a.run.app"
              readOnly
              defaultValue={process.env.NEXT_PUBLIC_API_URL ?? ""}
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-slate-400">
              GCP Project ID
            </label>
            <input
              className="input"
              placeholder="vardryn-grc-prod"
              readOnly
              defaultValue={process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID ?? ""}
            />
          </div>
        </div>
      </section>
    </div>
  );
}
