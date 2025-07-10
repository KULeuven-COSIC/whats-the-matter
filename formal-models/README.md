# Formal Models

This directory contains our annotated ProVerif models.

### Files:
- **case-resumption.pv**: CASE + CASE with resumption: adding Matter's resumption protocol to **case.pv**. 
- **case-resumption.out.pv**: The output log of **case-resumption.pv** (without Phase 3).
- **case.pv**: CASE: Matter's specification of the SIGMA-I protocol.
- **case.out.pv**: The output log of **case.pv**.
- **pase.pv**: PASE: Matter's specification of SPAKE2+ protocol.
- **pase.pv.out**: The output log of **pase.pv**.
- **sigma.pv**: The SIGMA-I protocol as described in Krawczyk's paper.
- **sigma.pv.out**: The output log of **sigma.pv**.
- **spake2p.pv**: The original SPAKE2+ protocol as described in its final RFC version.
- **spake2p.pv.out**: The output log of **spake2p.pv**.

Note: Please consult **case.pv** before **case-resumption.pv**.

To run our models, you only require installing ProVerif.
Detailed instructions on how to do that is can be found on the project's [official page](https://bblanche.gitlabpages.inria.fr/proverif/README).

After installing, you may run:

```bash
./proverif <filename>.pv
```

#### Additional Notes
- The output we provide was the result of running our models with ProVerif v2.05.
- ProVerif is single-threaded, so it would not benefit from a lot of cores.
- Approximate Running Times (On a very fast CPU):
	- **spake2p.pv** and **pase.pv** took a bit more than an hour.
	- **case.pv** ~15 mins.
	- **case-resumption.pv** ~5 mins without phase 3 and ~30 mins with phase 3.
	- **sigma.pv** should be rather quick, because it's a simple model.
