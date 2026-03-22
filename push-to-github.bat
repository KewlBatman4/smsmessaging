@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "REPO_URL=https://github.com/KewlBatman4/smsmessaging.git"

if not exist ".git" (
  echo [1/4] Initialising git repo...
  git init
  if errorlevel 1 goto :fail
  git branch -M main
  git remote add origin "%REPO_URL%"
  if errorlevel 1 goto :fail
  echo Remote added: %REPO_URL%
) else (
  git remote get-url origin >nul 2>&1
  if errorlevel 1 (
    echo Adding remote origin...
    git remote add origin "%REPO_URL%"
    if errorlevel 1 goto :fail
  )
)

echo [2/4] Staging all files in backend folder...
git add -A

git diff --cached --quiet
if errorlevel 1 (
  set /p "MSG=Commit message ^(Enter for: Update backend^): "
  if "!MSG!"=="" set "MSG=Update backend"
  echo [3/4] Committing...
  git commit -m "!MSG!"
  if errorlevel 1 (
    echo [ERROR] git commit failed.
    pause
    exit /b 1
  )
) else (
  echo Nothing new to commit.
  echo [3/4] Skipping commit.
)

echo [4/4] Pushing to GitHub...
git push -u origin main
if errorlevel 1 (
  echo.
  echo [ERROR] git push failed. If the repo is empty on GitHub, try again after fixing auth.
  echo Repo: https://github.com/KewlBatman4/smsmessaging
  pause
  exit /b 1
)

echo.
echo Done. https://github.com/KewlBatman4/smsmessaging
pause
exit /b 0

:fail
echo [ERROR] A git command failed.
pause
exit /b 1
