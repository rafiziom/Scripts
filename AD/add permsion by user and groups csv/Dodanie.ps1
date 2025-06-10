<#
.SYNOPSIS
    Zarz�dza cz�onkostwem wielu u�ytkownik�w w grupach AD na podstawie mapowania z pliku CSV.
    Tylko dla okre�lonych grup - usuwa u�ytkownika, je�li nie jest na li�cie CSV.
.DESCRIPTION
    Skrypt importuje dane z pliku CSV. Dla ka�dego wiersza (u�ytkownika):
    1. Odczytuje login u�ytkownika z dedykowanej kolumny (domy�lnie 'UserLogin').
    2. Odczytuje nazwy grup z kolumn.
    3. Usuwa u�ytkownika z grup (je�li istnieje) je�li nie jest w CSV.
    4. Dodaje u�ytkownika do grup je�li jest w CSV.
    5. Generuje raport z wykonanych operacji.
.PARAMETER CsvInputPath
    �cie�ka do pliku CSV zawieraj�cego mapowania u�ytkownik�w do grup.
    Pierwsza kolumna powinna zawiera� login u�ytkownika, kolejne - przypisane grupy.
.PARAMETER CsvUserColumnName
    Nazwa kolumny w pliku CSV, kt�ra zawiera login u�ytkownika (SamAccountName). Domy�lnie "UserLogin".
.PARAMETER CsvDelimiter
    Znak u�ywany jako separator w pliku CSV. Domy�lnie "," (przecinek). U�yj "`t" dla tabulatora, ";" dla �rednika itp.
.PARAMETER ReportPath
    �cie�ka do pliku CSV, w kt�rym zostanie zapisany raport.
.EXAMPLE
    # U�ycie z domy�lnymi ustawieniami (plik CSV oddzielony przecinkami, kolumna loginu 'UserLogin')
    .\Set-UserGroupsFromCsvWide.ps1 -CsvInputPath "C:\Temp\UserGroupsAssignment.csv" -ReportPath "C:\Temp\RaportUprawnien.txt"

.EXAMPLE
    # U�ycie z plikiem CSV oddzielonym �rednikami, gdzie kolumna z loginem nazywa si� "Login"
    .\Set-UserGroupsFromCsvWide.ps1 -CsvInputPath "C:\Temp\UserGroupsSemicolon.csv" -CsvUserColumnName "Login" -CsvDelimiter ";" -ReportPath "C:\Temp\RaportUprawnien.txt"
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$CsvInputPath,

    [Parameter(Mandatory = $false)]
    [string]$CsvUserColumnName = "UserLogin",

    [Parameter(Mandatory = $false)]
    [string]$CsvDelimiter = ";",

    [Parameter(Mandatory = $true)]
    [string]$ReportPath
)

# Lista DOZWOLONYCH grup
$allowedGroups = @(
    "Administrator",
    "StockTakingProcesorManager",
    "ChecklistProcessorManager",
    "ChecklistUser",
    "StockUser",
    "CoachingProcessorManager",
    "CoachingUser",
    "HQChecklistProcessorManager",
    "MarketingTaskUser",
    "MarketingTaskEditor",
    "OperationalTaskUser",
    "OperationalTaskEditor",
    "HRTaskUser",
    "HRTaskManager"
)

# Sprawdzenie, czy modu� Active Directory jest dost�pny
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Modu� Active Directory dla PowerShell nie jest zainstalowany lub dost�pny. Zainstaluj RSAT lub uruchom skrypt na serwerze z AD DS."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$reportData = @()
$scriptStartTime = Get-Date # U�yjemy tej samej sygnatury czasowej dla wszystkich wpis�w w raporcie z jednego uruchomienia

Function Log-Action {
    param (
        [string]$User,
        [string]$Group,
        [string]$Action,
        [string]$Status,
        [string]$Message
    )
    Write-Host "Log-Action: User=$User, Group=$Group, Action=$Action, Status=$Status, Message=$Message" # Dodane debugowanie
    
    # Bezpo�redni zapis do pliku w funkcji Log-Action
    $logLine = "{0} - User: {1}, Group: {2}, Action: {3}, Status: {4}, Message: {5}" -f `
        $scriptStartTime.ToString("yyyy-MM-dd HH:mm:ss"),
        $User,
        $Group,
        $Action,
        $Status,
        $Message
    
    try {
        Add-Content -Path $ReportPath -Value $logLine
    } catch {
        Write-Error "B��d zapisu do pliku w Log-Action: $($_.Exception.Message)"
    }

    $reportData += [PSCustomObject]@{
        Timestamp   = $scriptStartTime.ToString("yyyy-MM-dd HH:mm:ss")
        User        = $User
        Group       = $Group
        Action      = $Action
        Status      = $Status
        Message     = $Message
    }
}

# --- G��WNA LOGIKA ---

Write-Host "Start: Sprawdzanie pliku CSV: $CsvInputPath" # Dodane debugowanie

if (-not (Test-Path $CsvInputPath)) {
    Write-Error "Plik CSV '$CsvInputPath' nie zosta� znaleziony."
    Log-Action -User "SYSTEM" -Group "N/A" -Action "Inicjalizacja" -Status "B��d" -Message "Plik CSV '$CsvInputPath' nie zosta� znaleziony."
    Write-Host "Exit: Plik CSV nie znaleziony" # Dodane debugowanie
    exit 1
}

Write-Host "Start: Importowanie pliku CSV" # Dodane debugowanie
try {
    $allRowsFromCsv = Import-Csv -Path $CsvInputPath -Delimiter $CsvDelimiter -ErrorAction Stop
    Write-Host "Success: Plik CSV zaimportowany" # Dodane debugowanie
}
catch {
    Write-Error "B��d podczas odczytu pliku CSV '$CsvInputPath' z separatorem '$CsvDelimiter': $($_.Exception.Message)"
    Log-Action -User "SYSTEM" -Group "N/A" -Action "Odczyt CSV" -Status "B��d" -Message "B��d odczytu CSV: $($_.Exception.Message)"
    Write-Host "Exit: B��d importu CSV" # Dodane debugowanie
    exit 1
}

if (-not $allRowsFromCsv -or $allRowsFromCsv.Count -eq 0) {
    Write-Warning "Plik CSV '$CsvInputPath' jest pusty lub nie zawiera danych."
    Log-Action -User "SYSTEM" -Group "N/A" -Action "Odczyt CSV" -Status "Ostrze�enie" -Message "Plik CSV '$CsvInputPath' jest pusty."
    Write-Host "Exit: Plik CSV pusty" # Dodane debugowanie
    exit 0
}

Write-Host "Start: Sprawdzanie kolumny u�ytkownika: $CsvUserColumnName" # Dodane debugowanie
if (-not ($allRowsFromCsv[0].PSObject.Properties.Name -contains $CsvUserColumnName)) {
    Write-Error "Plik CSV '$CsvInputPath' musi zawiera� kolumn� o nazwie '$CsvUserColumnName' (okre�lona parametrem -CsvUserColumnName)."
    Log-Action -User "SYSTEM" -Group "N/A" -Action "Odczyt CSV" -Status "B��d" -Message "Brak kolumny '$CsvUserColumnName' w nag��wkach pliku CSV."
    Write-Host "Exit: Brak kolumny u�ytkownika" # Dodane debugowanie
    exit 1
}

# Pobranie listy wszystkich unikalnych nazw grup z ca�ego pliku CSV (ze wszystkich kolumn opr�cz CsvUserColumnName)
Write-Host "Start: Pobieranie unikalnych nazw grup" # Dodane debugowanie
$allDistinctGroupNamesFromCsv = @()
foreach ($csvRowObject in $allRowsFromCsv) {
    Write-Host "Przetwarzanie wiersza CSV" # Dodane debugowanie
    $csvRowObject.PSObject.Properties | ForEach-Object {
        if ($_.Name -ne $CsvUserColumnName) { # Pomijamy kolumn� z loginem u�ytkownika
            $groupNameValue = $_.Value
            if (-not [string]::IsNullOrWhiteSpace($groupNameValue)) {
                $allDistinctGroupNamesFromCsv += $groupNameValue.Trim()
            }
        }
    }
}
$allDistinctGroupNamesFromCsv = $allDistinctGroupNamesFromCsv | Select-Object -Unique | Sort-Object

# Weryfikacja istnienia w AD WSZYSTKICH unikalnych grup wymienionych w CSV i zbudowanie listy "zarz�dzanych" grup, kt�re istniej� w AD
Write-Host "Start: Weryfikacja grup w AD" # Dodane debugowanie
$allManagedAndExistingAdGroups_Objects = @()
$allManagedAndExistingAdGroup_SamNames = @()
Write-Host "Weryfikowanie istnienia w AD wszystkich unikalnych grup wymienionych w pliku CSV..."
foreach ($groupNameInCsv in $allDistinctGroupNamesFromCsv) {
    # Tylko DOZWOLONE grupy
    if ($groupNameInCsv -in $allowedGroups) {
        try {
            $adGroup = Get-ADGroup -Identity $groupNameInCsv -ErrorAction Stop
            $allManagedAndExistingAdGroups_Objects += $adGroup
            $allManagedAndExistingAdGroup_SamNames += $adGroup.SamAccountName
            Log-Action -User "SYSTEM" -Group $groupNameInCsv -Action "Globalna weryfikacja grupy" -Status "Powodzenie" -Message "Grupa istnieje w AD i jest zarz�dzana."
        }
        catch {
            Write-Warning "Grupa '$groupNameInCsv' (wymieniona w CSV) nie istnieje w Active Directory lub wyst�pi� b��d: $($_.Exception.Message)"
            Log-Action -User "SYSTEM" -Group $groupNameInCsv -Action "Globalna weryfikacja grupy" -Status "B��d" -Message "Grupa nie istnieje w AD. Nie b�dzie mo�na ni� zarz�dza�."
        }
    } else {
        Write-Host "Grupa '$groupNameInCsv' nie jest na li�cie dozwolonych. Pomijam."
    }
}
$allManagedAndExistingAdGroup_SamNames = $allManagedAndExistingAdGroup_SamNames | Sort-Object -Unique
Write-Host "Grupy zarz�dzane przez ten skrypt (istniej�ce w AD i wymienione w CSV): $($allManagedAndExistingAdGroup_SamNames -join ', ')"
Write-Host "-----------------------------------------------------------------"
Write-Host "Success: Zweryfikowano grupy w AD" # Dodane debugowanie


# Przetwarzanie ka�dego wiersza (u�ytkownika) z pliku CSV
Write-Host "Start: Przetwarzanie u�ytkownik�w z CSV" # Dodane debugowanie
foreach ($csvRowObject in $allRowsFromCsv) {
    $currentUserLogin = $csvRowObject.$CsvUserColumnName.Trim()
    
    if ([string]::IsNullOrWhiteSpace($currentUserLogin)) {
        Write-Warning "Pomini�to wiersz z pustym loginem u�ytkownika w kolumnie '$CsvUserColumnName'."
        Log-Action -User "N/A (pusty)" -Group "N/A" -Action "Przetwarzanie wiersza CSV" -Status "Ostrze�enie" -Message "Pusty login u�ytkownika w wierszu."
        continue
    }

    Write-Host ""
    Write-Host "--- Przetwarzanie u�ytkownika: $currentUserLogin ---"

    # Lista docelowych nazw grup dla TEGO u�ytkownika z jego wiersza w CSV
    $targetGroupNamesForThisUser_FromCsvRow = @()
    $csvRowObject.PSObject.Properties | ForEach-Object {
        if ($_.Name -ne $CsvUserColumnName) {
            $groupNameValue = $_.Value
            if (-not [string]::IsNullOrWhiteSpace($groupNameValue)) {
                $targetGroupNamesForThisUser_FromCsvRow += $groupNameValue.Trim()
            }
        }
    }
    $targetGroupNamesForThisUser_FromCsvRow = $targetGroupNamesForThisUser_FromCsvRow | Select-Object -Unique

    # Grupy, kt�re u�ytkownik powinien mie� (te z jego listy w CSV, kt�re FAKTYCZNIE istniej� w AD i s� zarz�dzane)
    $validTargetGroupNamesForThisUser = $targetGroupNamesForThisUser_FromCsvRow | Where-Object { $_ -in $allManagedAndExistingAdGroup_SamNames } | Sort-Object -Unique

    $adUser = $null
    try {
        $adUser = Get-ADUser -Identity $currentUserLogin -Properties MemberOf -ErrorAction Stop
        Write-Host "Znaleziono u�ytkownika: $($adUser.SamAccountName)"
    }
    catch {
        Write-Error "Nie mo�na znale�� u�ytkownika o loginie '$currentUserLogin': $($_.Exception.Message)"
        Log-Action -User $currentUserLogin -Group "N/A" -Action "Weryfikacja u�ytkownika" -Status "B��d" -Message "U�ytkownik '$currentUserLogin' nie znaleziono."
        continue
    }

    # Iteracja po WSZYSTKICH dozwolonych grupach i sprawdzenie, czy u�ytkownik powinien w nich by�
    foreach ($allowedGroup in $allowedGroups) {
        # Czy u�ytkownik POWINIEN by� w tej grupie (zgodnie z CSV)?
        if ($allowedGroup -in $validTargetGroupNamesForThisUser) {
            # U�ytkownik powinien by� w tej grupie, wi�c nic nie robimy (sprawdzimy p�niej, czy faktycznie jest)
            Write-Host "U�ytkownik '$currentUserLogin' powinien by� w grupie '$allowedGroup' (zgodnie z CSV)."
        } else {
            # U�ytkownik NIE powinien by� w tej grupie, wi�c sprawdzamy, czy w niej jest i ew. usuwamy
            try {
                # Pobierz wszystkich cz�onk�w grupy
                $groupMembers = Get-ADGroupMember -Identity $allowedGroup -ErrorAction Stop

                # Sprawd�, czy u�ytkownik jest na li�cie cz�onk�w
                $isMember = $groupMembers | Where-Object {$_.SamAccountName -eq $adUser.SamAccountName}

                if ($isMember) {
                    # U�ytkownik JEST w grupie, a NIE powinien, wi�c go usuwamy
                    Write-Host "Usuwanie '$currentUserLogin' z grupy '$allowedGroup'..."
                    Remove-ADGroupMember -Identity $allowedGroup -Members $adUser -Confirm:$false -ErrorAction Stop
                    Log-Action -User $currentUserLogin -Group $allowedGroup -Action "Usuni�to z grupy" -Status "Powodzenie" -Message "U�ytkownik usuni�ty (nie ma go w CSV)."
                } else {
                    # U�ytkownik NIE JEST w grupie i NIE powinien, wi�c nic nie robimy
                    Write-Host "U�ytkownik '$currentUserLogin' nie jest w grupie '$allowedGroup' i nie powinien."
                }
            } catch {
                Write-Error "B��d podczas sprawdzania/usuwania '$currentUserLogin' z grupy '$allowedGroup': $($_.Exception.Message)"
                Log-Action -User $currentUserLogin -Group $allowedGroup -Action "Sprawdzenie/Usuni�cie z grupy" -Status "B��d" -Message "Nie uda�o si� sprawdzi�/usun��: $($_.Exception.Message)"
            }
        }
    }

    # 1. Grupy do DODANIA (teraz ta logika jest mniej istotna, bo g��wny nacisk jest na usuwanie)
    $groupsToAddForThisUser = $validTargetGroupNamesForThisUser | Where-Object { $_ -notin $currentUserAdGroupSamAccountNames }
    foreach ($groupNameToAdd in $groupsToAddForThisUser) {
        $adGroupObjToAdd = $allManagedAndExistingAdGroups_Objects | Where-Object {$_.SamAccountName -eq $groupNameToAdd} | Select-Object -First 1
        if ($adGroupObjToAdd) {
            Write-Host "Dodawanie '$currentUserLogin' do grupy '$($adGroupObjToAdd.SamAccountName)'..."
            try {
                Add-ADGroupMember -Identity $adGroupObjToAdd -Members $adUser -ErrorAction Stop
                Log-Action -User $currentUserLogin -Group $adGroupObjToAdd.SamAccountName -Action "Dodano do grupy" -Status "Powodzenie" -Message "U�ytkownik dodany."
            }
            catch {
                Write-Error "B��d dodawania '$currentUserLogin' do '$($adGroupObjToAdd.SamAccountName)': $($_.Exception.Message)"
                Log-Action -User $currentUserLogin -Group $adGroupObjToAdd.SamAccountName -Action "Dodano do grupy" -Status "B��d" -Message "Nie uda�o si� doda�: $($_.Exception.Message)"
            }
        }
    }
}
Write-Host "Success: Przetwarzanie u�ytkownik�w zako�czone" # Dodane debugowanie

Write-Host "Zako�czono przetwarzanie wszystkich u�ytkownik�w."
