A disposable AI coding workspace in your browser, powered by DeepSeek Harness and your OpenRouter key or ChatGPT subscription. Deploy to Cloudflare in one click.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/kodareef5/dsh-cloudflare)

Set the `DSH_UNLOCK_KEY` Worker secret to a random key (`openssl rand -hex 32`). Paste it to unlock, or open `https://your-worker/#key=YOUR_KEY`; anyone with this link has access. Existing deployments must add the secret before updating.

Unlocks last eight hours in an HttpOnly session cookie. Rotating the secret revokes them. Fetch, Git clone and the OpenAI relay share a limit of roughly 60 requests/minute per Cloudflare location. Rejected requests still use your Worker quota. AI credentials stay separate.
