# 上架流程（Chrome Web Store／Microsoft Edge Add-ons）

更新已上架的版本：推版本 tag → GitHub 等你核准 → 自動上傳兩家商店並送審。
流程檔 `.github/workflows/release.yml`，上架腳本 `scripts/release/`（Chrome Web Store API v2、Edge Add-ons API v1.1）。

不會自動化的部分（API 不支援，需在後台手動）：說明文字、截圖、權限用途說明。審核由 Google／Microsoft 進行，無法略過。

## 一次性設定

### 1. Chrome：service account

1. [Google Cloud Console](https://console.cloud.google.com/) 建立或選一個專案，啟用 **Chrome Web Store API**。
2. IAM 與管理 → 服務帳戶 → 建立服務帳戶（不需授予角色）→ 金鑰 → 新增 **JSON** 金鑰並下載。
3. [Chrome Web Store 開發人員資訊主頁](https://chrome.google.com/webstore/devconsole) → **Account** → 加入服務帳戶的 email。每個發布者只能加一個；Google 帳號須已開啟兩步驟驗證。
4. 記下 **發布者 ID**（Publisher → Settings）與 **擴充功能 ID**（項目頁網址中的 32 字元 ID）。

### 2. Edge：API 憑證

1. [Partner Center](https://partner.microsoft.com/dashboard/microsoftedge/publishapi) → Microsoft Edge → **Publish API**（若出現 "enable the new experience" 先按 Enable）→ **Create API credentials**。
2. 記下 **Client ID** 與 **API key**（API key 有到期日，到期前要重新產生）。
3. 擴充功能的 Overview 頁 → Extension identity → **Product ID**。

### 3. GitHub Environment

Repo → Settings → Environments → New environment，名稱 **`store`**：

- **Required reviewers**：加入自己（不要勾 "Prevent self-review"，否則自己無法核准）。
- **Deployment branches and tags**：Selected → 加入 tag 規則 `v*` 與分支 `master`。
- **Environment secrets**：

| 名稱 | 內容 |
|---|---|
| `CWS_PUBLISHER_ID` | Chrome 發布者 ID |
| `CWS_EXTENSION_ID` | Chrome 擴充功能 ID |
| `CWS_SERVICE_ACCOUNT_JSON` | 下載的 JSON 金鑰檔**整份內容** |
| `EDGE_PRODUCT_ID` | Edge Product ID |
| `EDGE_CLIENT_ID` | Edge Client ID |
| `EDGE_API_KEY` | Edge API key |

JSON 金鑰貼進 secret 後，刪除本機下載的檔案。

### 4. 驗證設定（不會上傳）

Actions → **Release to browser stores** → Run workflow → 勾選 **check_only** → 核准。
成功時 log 會顯示 Chrome 目前上架的版本；Edge 沒有唯讀 API，只檢查 secret 是否齊全。

## 每次發版

1. 後台有變動先手動更新：說明（`store/description-*.md`）、截圖；**新增權限時**先在 Chrome「隱私權」頁填用途說明（`store/privacy-practices.md`），否則送審可能被擋。
2. 改 `package.json` 的 `version`（版本號唯一來源，manifest 由它產生），commit 到 master。
3. 推 tag：`git tag v1.0.5 && git push origin v1.0.5`（必須與 package.json 相同，否則流程停止）。
4. GitHub 通知 → Review deployments → 確認 commit 與版本無誤 → **Approve**：上傳兩家並送審。
5. 審核通常數天，最長數週。手動執行時可選 Chrome `STAGED_PUBLISH`：審核通過後到後台再按發布。

## 常見錯誤

| 訊息 | 原因／處理 |
|---|---|
| Chrome upload ended in state FAILED | 版本號未高於已上架版本，或套件被拒；看 log 中商店回應 |
| Google token request failed `invalid_grant` | JSON 金鑰失效或被刪；重建金鑰並更新 secret |
| Chrome fetchStatus failed 403／404 | 服務帳戶未加入 Developer Dashboard Account，或 ID 錯誤 |
| Edge ... `[InProgressSubmission]` | 上一版仍在審核中，等審核完成再送 |
| Edge ... HTTP 401 | API key 到期或錯誤；Partner Center 重新產生並更新 secret |
| 一家成功、另一家失敗 | 不要重推 tag（已送出的那家會因版本相同而失敗）。修正後手動 Run workflow，`store` 只選失敗的那家 |
| missing environment variables | 推 tag 一律送兩家；只設定一家時改用手動 Run workflow 並選該家 |
| Tag ... is not on master | tag 須指向 master 上的 commit；先合併再打 tag |

Chrome Web Store API v1.1 於 2026-10-15 停用，本流程使用 v2；`wxt submit`（publish-browser-extension 3.x）仍走 v1.1，不要再用於 Chrome。
