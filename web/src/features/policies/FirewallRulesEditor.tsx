import { Plus, Trash2 } from 'lucide-react';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { EMPTY_RULE, MAX_FIREWALL_RULES, type FirewallRuleForm } from './firewall-rules';

/** Edits the rule list of a `firewall.rules` policy. */
export function FirewallRulesEditor({
  rules,
  error,
  onChange,
}: {
  rules: FirewallRuleForm[];
  error: string | null;
  onChange: (rules: FirewallRuleForm[]) => void;
}) {
  const update = (i: number, patch: Partial<FirewallRuleForm>) => {
    onChange(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  };
  return (
    <fieldset className="grid gap-3">
      <legend className="mb-1 text-sm font-medium">Rules</legend>
      <p className="text-muted-foreground text-xs">
        Rules are named &quot;DranzoRMM: …&quot; in Windows Firewall and live in table inet dranzormm (Linux, nftables)
        or pf anchor com.apple/250.DranzoRMM (macOS). Program rules apply on Windows only. On Linux an Allow rule cannot
        override a block in another firewall.
      </p>
      {rules.map((r, i) => {
        const id = `fw-rule-${String(i)}`;
        return (
          <div key={id} className="grid gap-2 rounded-md border p-3 sm:grid-cols-6">
            <div className="grid gap-1 text-xs sm:col-span-2">
              <Label htmlFor={`${id}-name`}>Name</Label>
              <Input
                id={`${id}-name`}
                value={r.name}
                maxLength={64}
                onChange={(e) => {
                  update(i, { name: e.target.value });
                }}
              />
            </div>
            <div className="grid gap-1 text-xs">
              <Label htmlFor={`${id}-action`}>Action</Label>
              <NativeSelect
                id={`${id}-action`}
                value={r.action}
                onChange={(e) => {
                  update(i, { action: e.target.value as FirewallRuleForm['action'] });
                }}
              >
                <NativeSelectOption value="block">Block</NativeSelectOption>
                <NativeSelectOption value="allow">Allow</NativeSelectOption>
              </NativeSelect>
            </div>
            <div className="grid gap-1 text-xs">
              <Label htmlFor={`${id}-direction`}>Direction</Label>
              <NativeSelect
                id={`${id}-direction`}
                value={r.direction}
                onChange={(e) => {
                  update(i, { direction: e.target.value as FirewallRuleForm['direction'] });
                }}
              >
                <NativeSelectOption value="in">Incoming</NativeSelectOption>
                <NativeSelectOption value="out">Outgoing</NativeSelectOption>
              </NativeSelect>
            </div>
            <div className="grid gap-1 text-xs">
              <Label htmlFor={`${id}-protocol`}>Protocol</Label>
              <NativeSelect
                id={`${id}-protocol`}
                value={r.protocol}
                onChange={(e) => {
                  const protocol = e.target.value as FirewallRuleForm['protocol'];
                  update(i, protocol === 'any' ? { protocol, ports: '' } : { protocol });
                }}
              >
                <NativeSelectOption value="tcp">TCP</NativeSelectOption>
                <NativeSelectOption value="udp">UDP</NativeSelectOption>
                <NativeSelectOption value="any">Any</NativeSelectOption>
              </NativeSelect>
            </div>
            <div className="flex items-end justify-end">
              <Button
                type="button"
                variant="ghost"
                size="icon"
                aria-label={`Remove rule ${String(i + 1)}`}
                onClick={() => {
                  onChange(rules.filter((_, j) => j !== i));
                }}
              >
                <Trash2 aria-hidden="true" />
              </Button>
            </div>
            <div className="grid gap-1 text-xs sm:col-span-2">
              <Label htmlFor={`${id}-ports`}>{r.direction === 'in' ? 'Local ports' : 'Remote ports'}</Label>
              <Input
                id={`${id}-ports`}
                className="ident"
                placeholder={r.protocol === 'any' ? 'Needs TCP or UDP' : '445, 8000-8100 (empty: all)'}
                disabled={r.protocol === 'any'}
                value={r.ports}
                onChange={(e) => {
                  update(i, { ports: e.target.value });
                }}
              />
            </div>
            <div className="grid gap-1 text-xs sm:col-span-2">
              <Label htmlFor={`${id}-addresses`}>{r.direction === 'in' ? 'From addresses' : 'To addresses'}</Label>
              <Input
                id={`${id}-addresses`}
                className="ident"
                placeholder="10.0.0.0/8, 203.0.113.9 (empty: any)"
                value={r.remoteAddresses}
                onChange={(e) => {
                  update(i, { remoteAddresses: e.target.value });
                }}
              />
            </div>
            <div className="grid gap-1 text-xs sm:col-span-2">
              <Label htmlFor={`${id}-program`}>Program (Windows, optional)</Label>
              <Input
                id={`${id}-program`}
                className="ident"
                placeholder="C:\Program Files\App\app.exe"
                value={r.program}
                onChange={(e) => {
                  update(i, { program: e.target.value });
                }}
              />
            </div>
          </div>
        );
      })}
      {error ? (
        <InlineAlert tone="danger" title="Check the rules">
          {error}
        </InlineAlert>
      ) : null}
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={rules.length >= MAX_FIREWALL_RULES}
          onClick={() => {
            onChange([...rules, { ...EMPTY_RULE }]);
          }}
        >
          <Plus aria-hidden="true" />
          Add rule
        </Button>
      </div>
    </fieldset>
  );
}
