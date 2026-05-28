$pdflatex = "D:\PFE PROJECT\texlive\2026\bin\windows\pdflatex.exe"
$bibtex = "D:\PFE PROJECT\texlive\2026\bin\windows\bibtex.exe"
$workdir = "D:\PFE PROJECT\PFE_Report (1)"

Start-Process -FilePath $pdflatex -ArgumentList "-interaction=nonstopmode main.tex" -WorkingDirectory $workdir -NoNewWindow -Wait
Start-Process -FilePath $bibtex -ArgumentList "main" -WorkingDirectory $workdir -NoNewWindow -Wait
Start-Process -FilePath $pdflatex -ArgumentList "-interaction=nonstopmode main.tex" -WorkingDirectory $workdir -NoNewWindow -Wait
Start-Process -FilePath $pdflatex -ArgumentList "-interaction=nonstopmode main.tex" -WorkingDirectory $workdir -NoNewWindow -Wait
