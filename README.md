---
tags: [readme, frontend, project/n0x]
aliases: [Frontend README, Project Root]
---

> Navigation: [[MAP|Map]] · [[CLI_FEATURES_SPEC|CLI Spec]] · [[BACKEND_SPEC|Backend Spec]] · **Frontend README** · [[n0x-cli-rs/README|CLI README]]

<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

> Project hub: [[MAP]]. The Rust analysis backend lives in [[n0x-cli-rs/README|n0x-cli-rs]] and is the source of truth for every reverse-engineering capability.

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/34a430df-e470-4eb3-bd7f-3d25bdf7eb62

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Run CLI Workspace

For a terminal-first workflow with technical UI/UX styling:

1. Install dependencies:
   `npm install`
2. Start the CLI:
   `npm run cli`
3. Type `help` to list commands (`view`, `search`, `select`, `attach`, `hex`, `disasm`, `exit`)
