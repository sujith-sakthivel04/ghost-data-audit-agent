# Synthetic demo bundle

Every name, email address, user/resource ID, event, and record in this folder
was invented for the demo. These files do not contain challenge data or real
customer records. The bundle demonstrates an outstanding profile record, an
active data flow, a retained delivery log that exposes an email, and a separate
non-deletion request.

Run it from the product root with:

```bash
ghost-audit run \
  --requests examples/synthetic/bundle/requests.csv \
  --evidence-dir examples/synthetic/bundle/evidence \
  --output build/demo_output.csv
ghost-audit validate \
  --requests examples/synthetic/bundle/requests.csv \
  --output build/demo_output.csv
```
