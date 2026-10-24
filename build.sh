set -eu
root=$PWD
source_dir=$(mktemp -d)
trap 'rm -rf "$source_dir"' EXIT
export CI=true ELECTRON_SKIP_BINARY_DOWNLOAD=1 PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
rm -rf dist
git -C "$source_dir" init -q
git -C "$source_dir" fetch -q --depth=1 https://github.com/deepseek-ai/deepseek-harness.git 22ddee3792402c3e70ec5f86a63c3e3e895a2f60
git -C "$source_dir" checkout -q --detach FETCH_HEAD
git -C "$source_dir" apply --unidiff-zero "$root/openrouter.patch"
cd "$source_dir"
npx --yes pnpm@11.28.5 install --frozen-lockfile
node_modules/.bin/pnpm run build:flare
cp LICENSE apps/web/dist/LICENSE.txt
mv apps/web/dist "$root/dist"
