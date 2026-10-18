# n8n Cloud orchestration

Import [`workflows/n8n-visual-review.json`](../workflows/n8n-visual-review.json) to start a scanner job over HTTPS, poll its status, and review only new or visually changed candidate screenshots with **gpt-4o-mini**. The workflow is inactive, its optional schedule is disabled, and `ai_enabled` defaults to `false`. The AI request and assessment callback are wired, but that guard prevents fetching inline screenshots or calling OpenAI until you enable it. No account, credential, external AI call, or image upload was configured or performed while creating this export.

n8n Cloud coordinates the work; the Python scanner and Linux tools run on your own Linux server, natively or in Docker. Docker packages the scanner; n8n schedules and connects services. The [Execute Command node is unavailable on n8n Cloud](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.executecommand/), so the workflow uses HTTP. The [standalone scanner and local review interface](../standalone/README.md) can be used without n8n.

You can also schedule clients directly in the scanner UI, with independent full
enumeration and saved-inventory DNS/web cadences. Per-client intervals
and next due times persist on the Linux scanner, and require its server to remain
running. Choose one scheduling approach deliberately; enabling both a native
client schedule and an n8n trigger can create separate scan attempts. Stopping a
scanner run preserves its previous accepted results and leaves its future
schedules enabled; disable them separately when needed.

## Connect the scanner

1. Run the scanner on your Linux server. Set a private `TYPO_MONITOR_API_TOKEN` in its environment. Keep its application listener local and expose the authenticated `/api/` routes through an HTTPS reverse proxy reachable from n8n Cloud. Your machine's `127.0.0.1`, Docker service names, and private screenshot URLs are not reachable from n8n Cloud.
2. [Import the JSON file](https://docs.n8n.io/build/manage-workflows/export-and-import/). In **Configure monitor**, replace `https://scanner.example.invalid` with your reachable HTTPS API origin and set your scanner project UUID. These are editable fields; the workflow does not use `$env` or shell access.
3. Create a [Generic Header Auth credential](https://docs.n8n.io/integrations/builtin/credentials/httprequest/) named **TypoMonitorAPI**, with header `Authorization` and value `Bearer ` followed by the scanner token. Select it in **Start scan**, **Get run status**, **Get changed capture manifest**, **Fetch one inline image pair**, and **Save AI assessment**. Credential IDs and secrets are absent from the export.
4. Leave `ai_enabled=false` for the first manual test. The workflow starts/resumes the scanner and retrieves metadata only; it reports `ai_disabled`, zero AI requests, and zero saved assessments. It does not fetch image bytes into n8n.
5. To resume an existing job or review another page, set `existing_run_id` to its UUID. This skips job creation. **Start scan** has no automatic POST retry, avoiding duplicate jobs after an uncertain response.

The [HTTP Request node](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.httprequest/) uses a 30-second scanner-request timeout. Reads have bounded retries. Polling defaults to every 30 seconds with a 1,800-second deadline. Failed or cancelled scans and expired deadlines stop explicitly; ending an n8n execution does not cancel the independent scanner job. Keep these settings and the [workflow timeout](https://docs.n8n.io/build/manage-workflows/configure-workflow-settings/) within your Cloud plan's limit, then resume long jobs by run UUID. If you stop a scan in the scanner UI, the next status poll detects `cancelled` and ends with a stopped message. It does not enter image fetching or AI review for that cancelled run.

## Enable gpt-4o-mini review

In **Review with gpt-4o-mini**, select your existing [OpenAI credential](https://docs.n8n.io/integrations/builtin/credentials/openai/). This is n8n's native **OpenAI → Image → Analyze Image** node, version 2.3, using exactly `gpt-4o-mini`. You do not need to reveal or copy the key stored in n8n. The export contains no credential reference or secret. The [native image-operation documentation](https://docs.n8n.io/integrations/builtin/app-nodes/n8n-nodes-langchain.openai/image-operations/) describes its credential, model, and binary-image inputs.

After selecting credentials and checking the evidence-transfer scope below, set `ai_enabled=true` and test a small page, for example `review_limit=1`. The native node handles the OpenAI request; no HTTP Request node calls OpenAI. It has high image detail and an 800-token output cap. Its current [implementation](https://github.com/n8n-io/n8n/blob/master/packages/@n8n/nodes-langchain/nodes/vendors/OpenAi/v2/actions/image/analyze.operation.ts) uses the Responses API and exposes no JSON response-format or temperature setting for this operation. JSON is requested in the prompt and validated afterward. It does not switch models on access errors. Your account's credential and model access have not been tested. GPT-4o mini accepts image inputs and supports Responses. [Model documentation](https://developers.openai.com/api/docs/models/gpt-4o-mini).

The suggested prompt is included in **Configure monitor → review_prompt** and documented in [`workflows/AI_REVIEW_PROMPT.md`](../workflows/AI_REVIEW_PROMPT.md). Edit that field to customize it; candidate context and attachment order are appended automatically. Each item is one visual comparison request, not a dataset upload, model training job, or local AI run.

Each request labels the current screenshot, an optional previous screenshot of the same candidate and scheme, and up to one owned reference screenshot. The preparation node converts scanner PNG/JPEG data URLs into ordered n8n binary image fields, and the native node attaches those images. The prompt identifies each image by its position. The URL input mode splits values on commas and cannot safely carry data URLs; binary mode avoids that problem. No private scanner URL needs to be opened by OpenAI. [Image input guide](https://developers.openai.com/api/docs/guides/images-vision).

The prompt treats text inside pages as untrusted content, requests visible evidence and uncertainty, and gives the model no action tools. The native operation does not enforce a JSON schema. **Validate gpt-4o-mini response** rejects malformed or incomplete responses, refusals, unexpected models or tool outputs, invalid risk/summary/confidence fields, and a claimed change without a previous capture. Valid results are saved through the authenticated callback as AI assessments, separate from DNS findings. No model request is automatically retried, and a model/callback error stops that execution visibly. [Responses API specification](https://developers.openai.com/api/reference/resources/responses/methods/create).

Risk is `low`, `medium`, `high`, or `uncertain`; `changed` is a boolean or null; confidence is a finite number from zero to one. The model's confidence is its own estimate. Human review remains necessary: resemblance or a screenshot alone does not establish malicious intent or authoritative phishing detection. The workflow sends no notifications, exclusions, takedowns, or other external actions.

## Transfer size and batching

Unchanged screenshots, original seed captures, and likely parked domains are excluded from candidate review by the scanner selector. The workflow also skips captures with `current.analysis.reviewed_at` before fetching image bytes. With AI disabled, only run status and one metadata page enter n8n. With AI enabled, only the page's qualifying `new`/`changed` candidate pairs have inline images fetched, one pair at a time. These bytes then pass through n8n Cloud to OpenAI. An enabled pair sends **1–3 images**: one current, zero or one previous, and zero or one owned reference. Reference images can repeat in different candidate requests and contribute to input usage each time. No raw DNS inventory is included in the model prompt.

The default page cap is 5 candidate pairs, so it permits at most 5 model requests and 15 image inputs per execution; actual counts depend on available baselines/references. Set `review_limit` lower for testing; the workflow accepts 1–25 pairs per page. The scanner sends compact copies bounded to 1,280 pixels and 256 KiB per image (JPEG, or a smaller original PNG/JPEG); original disk screenshots remain unchanged. At the default cap, 15 images total at most 3.75 MiB of image bytes, or about 5 MiB of base64 before JSON overhead, if every pair has a previous image and reference. Model usage can incur charges. Already saved assessments are skipped on later runs. A model response that was received but not saved before an error may incur another call when retried manually.

The [Split Out node](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.splitout/) separates metadata items, and [Loop Over Items](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.splitinbatches/) processes one pair at a time. Final output includes request/save counts and explicit `has_more`, `next_offset`, and pagination warnings. To process another page, reuse `existing_run_id` and set `review_offset=next_offset`, including when a whole page was already reviewed and therefore admitted no candidates. Manifest/image requests use `include_reviewed=1` to keep page indices stable while callbacks save assessments; filtering happens after pagination. Pages do not continue automatically. Add a continuation workflow before claiming unattended review covers every page.

A loop bounds simultaneous work; n8n may still hold previous node outputs for an execution. Keep pages small and check [Cloud memory and execution-data retention](https://docs.n8n.io/deploy/use-n8n-cloud/configure-cloud/manage-your-data/). The export disables saved successful, failed, and manual execution data where workflow settings permit. Inspect your instance policy after import; this does not guarantee that no data is held in memory or retained by a provider.

## API contract

| Request | Result |
| --- | --- |
| `POST /api/scans` with `{"project_id":"UUID"}` | A run object containing `id`, `project_id`, `status`, and `discovery_mode`. Optional `"discovery_mode":"cached"` skips enumeration/generation; `"enumerate"` refreshes discovery. Omitting the field uses the project's saved default. |
| `GET /api/runs/UUID` | Run status: `running`, `completed`, `partial`, `failed`, or `cancelled`. Completed and partial runs can provide captured evidence. |
| `GET /api/runs/UUID/review?limit=5&offset=0&include_reviewed=1` | Metadata-only `run_id`, `items`, and `next_offset`. Review admits only `new`/`changed` pairs with a captured current image. |
| `GET /api/runs/UUID/review?include_images=1&domain=example.com&scheme=https&limit=1&offset=0&include_reviewed=1` | One pair with current and optional previous `image_data_url`, plus available owned references. Domain and scheme are required for inline images. |
| `POST /api/runs/UUID/reviews` | Saves `{domain, scheme, provider, model, summary, risk, changed, confidence}` as a labelled AI assessment. The workflow sets provider `OpenAI` and model `gpt-4o-mini`. |

After manual validation, choose a cadence in **Optional daily schedule** and publish the workflow. The example daily trigger is disabled and uses timezone `Europe/Amsterdam`. [Schedule Trigger publishing/timezone behavior](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.scheduletrigger/).

The export's JSON structure, node connections, and JavaScript transformations were checked locally with synthetic fixtures and official node schemas. It has not been imported into or executed on an n8n Cloud account, and no live AI request was made. Credential selection and your account's connectivity, plan limits, node compatibility, model access, and callback still need a deployment test.
