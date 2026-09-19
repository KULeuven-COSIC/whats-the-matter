# Formal Models

This directory contains our annotated ProVerif models. All model and output files are under [`proverif/`](proverif).

### Files:

- **case-resumption.pv**: CASE + CASE with resumption: adding Matter's resumption protocol to **case.pv**.
- **case-resumption.pv.out**: The output log of `case-resumption.pv` (without Phase 3).
- **case-resumption-patch.pv**: CASE + CASE with resumption with the patch proposed under Sect. 8.4 of the paper.
- **case-resumption-patch.pv.out**: The output log of `case-resumption-patch.pv` (without Phase 3).
- **case-resumption_leak_x.pv**: `case-resumption.pv` with the initiator's ephemeral key leaked. Shows the resumed session keys fall while the full-handshake keys hold.
- **case-resumption_leak_x.pv.out**: The output log of `case-resumption_leak_x.pv`.
- **case-resumption_leak_y.pv**: The same with the responder's ephemeral key leaked, so either key alone suffices.
- **case-resumption_leak_y.pv.out**: The output log of `case-resumption_leak_y.pv`.
- **case.pv**: CASE: Matter's specification of the SIGMA-I protocol.
- **case.pv.out**: The output log of `case.pv`.
- **pase.pv**: PASE: Matter's specification of the SPAKE2+ protocol.
- **pase.pv.out**: The output log of `pase.pv`.
- **pase_leak_w0.pv**:*`pase.pv` with the _w0-compromise_ tweak enabled (i.e., the derived verifier value `w0` is published on the public channel). It supports our claim that compromising `w0` gives the attacker an offline-guessing oracle for the setup passcode.
- **pase_leak_w0.pv.out**: The output log of `pase_leak_w0.pv`.
- **pase_leak_pw.pv**: **pase.pv** with the _forward-secrecy_ tweak enabled (i.e., the setup passcode `pw` is leaked to the attacker in phase 1). It shows that although the attacker obtains the passcode, the values established in earlier sessions remain secure.
- **pase_leak_pw.pv.out**: The output log of `pase_leak_pw.pv`.
- **sigma.pv**: The SIGMA-I protocol as described in Krawczyk's paper.
- **sigma.pv.out**: The output log of `sigma.pv`.
- **spake2p.pv**: The original SPAKE2+ protocol as described in its final RFC version.
- **spake2p.pv.out**: The output log of `spake2p.pv`.

Note: Please consult `case.pv` before `case-resumption.pv`.

Note: `pase_leak_w0.pv` and `pase_leak_pw.pv` are copies of **pase.pv** with exactly one of the leakage lines at the bottom of the main process uncommented. The corresponding "MODEL TWEAKS" comments in **pase.pv** document both scenarios.

## Installing ProVerif

You only need ProVerif. We used **v2.05**.

**macOS**

```bash
brew install opam
opam init -y && eval $(opam env)
opam install -y proverif
```

**Linux (Debian/Ubuntu)**

```bash
sudo apt update && sudo apt install -y opam
opam init --disable-sandboxing -y && eval $(opam env)
opam install -y proverif
```

Or download the source or binary package from the project's [official page](https://bblanche.gitlabpages.inria.fr/proverif/README) and follow its instructions.

ProVerif prints its version in the header of every run, so you can confirm it from the first lines of any output below.

## Running the models

```bash
cd proverif
proverif <filename>.pv
```

To check a result against ours, compare only the verdict lines:

```bash
proverif pase.pv > pase.mine.out
diff <(grep '^RESULT' pase.pv.out) <(grep '^RESULT' pase.mine.out)
```

#### Additional Notes

- The output we provide is the result of running our models with ProVerif v2.05.
- ProVerif is single-threaded, so it does not benefit from having many cores.
- Approximate running times (on a very fast CPU):
  - **spake2p.pv** took a bit more than an hour.
  - **pase.pv** ~3 mins.
  - **pase_leak_pw.pv** ~10 mins.
  - **pase_leak_w0.pv** ~10 mins.
  - **case.pv** ~15 mins.
  - **case-resumption.pv** <1 min without phase 3 and ~30 mins with phase 3.
  - **case-resumption-patch.pv** <2 min without phase 3 and ~1h5min with phase 3.
  - **case-resumption_leak{x, y}.pv** <1 min.
  - **sigma.pv** should be rather quick, because it's a simple model.
