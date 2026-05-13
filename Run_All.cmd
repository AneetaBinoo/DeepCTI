@echo off
set PYTHONPATH=%CD%\src
for %%M in (gemma4:e4b llama3.1:8b qwen2.5:14b mistral-nemo:12b gemma3:12b deepseek-r1:8b) do (
  set MODEL=%%M
  call :RUNONE %%M
)
python -m deepcti.evaluate_suggested --predictions runs\combined_all_models_predictions.jsonl --out-dir runs\combined_suggested_eval
exit /b

:RUNONE
set M=%1
set SAFE=%M::=_%
set SAFE=%SAFE:.=%
set SAFE=%SAFE:-=_%
ollama pull %M%
python -m deepcti.run_experiment --data-path ".\DeepCTI_LocalIntel_Eval_Dataset_Enhanced_References_100cases.xlsx" --out-dir runs\%SAFE%_suggested_full --models %M% --modes one_shot,no_memory,iterative --no-resume
copy /b runs\combined_all_models_predictions.jsonl + runs\%SAFE%_suggested_full\predictions.jsonl runs\combined_all_models_predictions.tmp >nul 2>nul
if exist runs\combined_all_models_predictions.tmp move /y runs\combined_all_models_predictions.tmp runs\combined_all_models_predictions.jsonl >nul
if not exist runs\combined_all_models_predictions.jsonl copy runs\%SAFE%_suggested_full\predictions.jsonl runs\combined_all_models_predictions.jsonl >nul
exit /b
