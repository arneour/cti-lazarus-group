@echo off
REM Week 5 lab: start ELK, download datasets, load them. Double-click or run from any folder.
cd /d "%~dp0"
echo === [1/4] Starting Elasticsearch + Kibana ===
docker compose up -d || goto :error
echo.
echo === [2/4] Waiting for Elasticsearch to be healthy (up to 3 min) ===
for /l %%i in (1,1,36) do (
  curl -s http://localhost:9200/_cluster/health | findstr "green yellow" >nul && goto :ready
  timeout /t 5 /nobreak >nul
)
echo Elasticsearch did not start in time. Run "docker compose logs elasticsearch" and send the output.
goto :error
:ready
docker compose ps
echo.
echo === [3/4] Downloading datasets ===
if exist data\ntds_volume_shadow_copy.json (echo already downloaded) else (python download_datasets.py || goto :error)
echo.
echo === [4/4] Loading into Elasticsearch ===
python load_to_elastic.py || goto :error
echo.
echo DONE. Open http://localhost:5601 -^> Discover -^> Try ES^|QL
pause
exit /b 0
:error
echo.
echo Something failed above. Take a screenshot of this window.
pause
exit /b 1
