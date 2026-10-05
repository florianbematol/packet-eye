// "Block this IP / app" button + confirmation dialog.

import { useState } from "react";
import { Ban, Loader2 } from "lucide-react";
import { Button, type ButtonProps } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useFirewallStore } from "@/store/firewallStore";
import type { BlockDirection, BlockTarget } from "@/lib/types";

interface Props {
  target: BlockTarget;
  /** Human label shown in the dialog, e.g. "1.2.3.4" or "chrome.exe". */
  label: string;
  buttonLabel?: string;
  defaultDirection?: BlockDirection;
  size?: ButtonProps["size"];
  variant?: ButtonProps["variant"];
  className?: string;
  disabled?: boolean;
  onDone?: () => void;
}

export default function BlockButton({
  target,
  label,
  buttonLabel = "Block",
  defaultDirection = "out",
  size = "sm",
  variant = "outline",
  className,
  disabled,
  onDone,
}: Props) {
  const block = useFirewallStore((s) => s.block);
  const [open, setOpen] = useState(false);
  const [direction, setDirection] = useState<BlockDirection>(defaultDirection);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await block(target, direction, note.trim() || undefined);
      setOpen(false);
      setNote("");
      onDone?.();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const kindLabel = target.kind === "ip" ? "address" : "application";

  return (
    <>
      <Button
        size={size}
        variant={variant}
        className={className}
        disabled={disabled}
        onClick={(e) => {
          e.stopPropagation();
          setError(null);
          setOpen(true);
        }}
        title={`Block this ${kindLabel} in Windows Firewall`}
      >
        <Ban className={buttonLabel ? "h-3.5 w-3.5 mr-1.5" : "h-3.5 w-3.5"} />
        {buttonLabel}
      </Button>
      <Dialog open={open} onOpenChange={(o) => !busy && setOpen(o)}>
        <DialogContent className="max-w-md" onClick={(e) => e.stopPropagation()}>
          <DialogHeader>
            <DialogTitle className="mono">Block {label}</DialogTitle>
            <DialogDescription>
              Creates a Windows Firewall rule in the <b>Packet Eye</b> group. You can
              disable or delete it at any time from the Firewall view. Requires the
              agent to run as Administrator.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Direction</Label>
              <Select value={direction} onValueChange={(v) => setDirection(v as BlockDirection)}>
                <SelectTrigger className="text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="text-xs">
                  <SelectItem value="out">Outbound (this PC → remote)</SelectItem>
                  <SelectItem value="in">Inbound (remote → this PC)</SelectItem>
                  <SelectItem value="both">Both directions</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Note (optional)</Label>
              <Input
                className="text-xs"
                placeholder="Why is this blocked?"
                maxLength={200}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
            {error && <div className="mono text-[11px] text-destructive break-all">{error}</div>}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirm} disabled={busy}>
              {busy ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Ban className="h-4 w-4 mr-2" />
              )}
              Block
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
