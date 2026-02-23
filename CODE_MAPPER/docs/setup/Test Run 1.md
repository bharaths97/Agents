# 1. Set up .env
cat > /Users/stumbleweed/Desktop/Website/Agents/CODE_MAPPER/.env << 'EOF'
OPENAI_API_KEY=sk-...your-key...
LOG_LEVEL=DEBUG
PHASE3_CROSS_FILE_ENABLED=true
SEMGREP_ENABLED=false
EOF

# 2. Create output dir
mkdir -p ~/code_mapper_results

# 3A. Run Docker with local repo path (existing flow)
cd /Users/stumbleweed/Desktop/Website/Agents/CODE_MAPPER
export REPO_PATH=~/your-repo
export OUTPUT_DIR=~/code_mapper_results
docker compose up --build

# 3B. Run Docker with remote repo URL (new auto-clone flow)
cd /Users/stumbleweed/Desktop/Website/Agents/CODE_MAPPER
export REPO_URL=https://github.com/user/your-repo.git
export REPO_BRANCH=main
export OUTPUT_DIR=~/code_mapper_results
docker compose up --build

# Optional clone controls for repo-url mode
# export REPO_COMMIT=<commit-sha>
# export REFRESH_CLONE=1

# 4. Clone failsafes in repo-url mode
# - retries clone attempts (default: 2)
# - shallow clone first (default depth: 1)
# - fallback to full clone when shallow clone is unsupported
# - cleans failed partial clones
# - reuses cached clone unless REFRESH_CLONE is set

# 5. View results
open ~/code_mapper_results/code_mapper_report_*.html
