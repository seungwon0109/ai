from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "cape_client.py"


def replace_once(old: str, new: str) -> None:
    text = PATH.read_text(encoding="utf-8")
    if new in text:
        return
    if text.count(old) != 1:
        raise RuntimeError(f"Patch marker mismatch: {old[:120]!r}")
    PATH.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(
        '''            try:\n                response = self.client.get(f"tasks/view/{task_id}/")\n            except httpx.HTTPError as exc:\n                raise CapeError(f"CAPE status request failed: {exc}") from exc\n''',
        '''            try:\n                response = self.client.get(f"tasks/view/{task_id}/")\n            except httpx.HTTPError as exc:\n                last_status = f"connection_error: {exc}"\n                delay = max(0.2, poll_interval)\n                if time.monotonic() + delay >= deadline:\n                    break\n                time.sleep(delay)\n                continue\n''',
    )
    replace_once(
        '''                except (CapeError, httpx.HTTPError) as exc:\n                    errors.append(str(exc))\n                    break\n''',
        '''                except httpx.HTTPError as exc:\n                    errors.append(str(exc))\n                    delay = max(0.2, poll_interval)\n                    if time.monotonic() + delay >= deadline:\n                        break\n                    time.sleep(delay)\n                    continue\n                except CapeError as exc:\n                    errors.append(str(exc))\n                    break\n''',
    )
    print("CAPE transient retry patch applied.")


if __name__ == "__main__":
    main()
