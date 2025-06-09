@echo off
cd C:\PSTools
set /p UserInputDes=Z jakim komputerem chcesz się polaczyc?
set /p AppDes=Jaką aplikacje uruchomic?
ps.exe \\%UserInputDes% %AppDes%
