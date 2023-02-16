--[[
 Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 or more contributor license agreements.  You may not install, use, modify,
 or distribute this file unless you have a valid commercial license from
 Elasticsearch B.V. or one of its affiliates. If you are interested in
 obtaining Elastic's permission to use this file, please contact
 elastic_license@elastic.co.
--]]

local utils = {}

-- ExtensionData creates an extension data table from the given arguments.
-- @param category int: Category of the extension.
-- @param lowEntropy boolean: True when the extension is known to have a low entropy.
-- @param magicBytes table: Represents the file magic bytes.
-- @return table: A table representing the extension data.
function utils.ExtensionData(category, lowEntropy, magicBytes)
    local obj = {}
    obj.category = category
    obj.lowEntropy = lowEntropy
    obj.magicBytes = magicBytes
    return obj
end

-- Returns the hexadecimal representation of the binary data. Every byte of data
-- is converted into the corresponding 2-digit hex representation. The returned
-- bytes object is therefore twice as long as the length of data.
-- @param buff string: Represents the binary data.
-- @return string: hexlified string.
function utils.Hexlify(buff)
    local t = {}

    for i = 1, #buff do
        table.insert(t, string.format('%02X', string.byte(string.sub(buff, i, i))))
    end

    return table.concat(t, '')
end

-- Split a string by a separator.
-- @param str string: The subject string.
-- @param sep string: The separator used to split the string.
-- @return table: A table representing the split string.
function utils.Split(str, sep)
    local result = {}
    local regex = ('([^%s]+)'):format(sep)
    for each in str:gmatch(regex) do
        table.insert(result, each)
    end
    return result
end

-- Returns a boolean representing if key exists in the provided table.
-- @param inputTable table: The subject table.
-- @param key string: The key to check for.
-- @return boolean: True if the key exists in the table.
function utils.TableHasKey(inputTable, key)
    return inputTable[key] ~= nil
end

-- Returns a boolean representing if value exists in the provided table.
-- @param inputTable table: The subject table.
-- @param value string: The value to check for.
-- @return boolean: True if the value exists in the table.
function utils.TableHasValue(inputTable, value)
    for _, v in ipairs(inputTable) do
        if v == value then
            return true
        end
    end

    return false
end

-- Performs a deep copy of an object. This function supports: tables as keys,
-- recursive tables, and preserves meta-tables.
-- @param obj table: The subject table.
-- @param seen table: A table meant to be ignored by the "outside" caller and
-- only used for recursive calls. It avoids repeated deep copying of tables that
-- occur more than once in a single table.
-- @param Table table: The newly copied table.
function utils.Copy(obj, seen)
    if type(obj) ~= 'table' then
        return obj
    end
    if seen and seen[obj] then
        return seen[obj]
    end
    local s = seen or {}
    local res = setmetatable({}, getmetatable(obj))
    s[obj] = res
    for k, v in pairs(obj) do
        res[utils.Copy(k, s)] = utils.Copy(v, s)
    end
    return res
end

-- Converts a byte string to an array of bytes.
-- @param str string: The subject string.
-- @return table: A table containing the resulted array of bytes.
function utils.StringToByteArray(str)
    local result = {}
    for i = 1, #str do
        table.insert(result, string.byte(str, i));
    end
    return result
end

-- Removes alternate data stream (if exists) from the provided file path,
-- e.g. C:\test.txt:Zone.Identifier => C:\test.txt.
-- @param str string: The subject file path.
-- @return string: The curated string if ADS is found. Otherwise, a copy of the string.
function utils.RemoveAdsFromPath(str)
    local volumeIndex = string.find(str, ':', nil, true)

    -- If we confirm the second character was a colon (e.g. 'C:'), then
    -- proceed with attempting to remove an ADS from the remaining path.
    if volumeIndex ~= nil then
        if volumeIndex == 2 then
            return utils.RemoveAdsFromExtension(str, volumeIndex + 1)
        end
    end

    return str
end

-- Removes alternate data stream (if exists) from the provided filename,
-- extension, or partial path. e.g. test.txt:Zone.Identifier => test.txt
-- @param str string: The subject file name.
-- @param startIndex integer: An index to start the search from.
-- @return string: The curated string if ADS is found. Otherwise, a copy of the string.
function utils.RemoveAdsFromExtension(str, startIndex)
    startIndex = startIndex or 1

    local adsIndex = string.find(str, ':', startIndex, true)
    if adsIndex ~= nil then
        return string.sub(str, startIndex, adsIndex - 1)
    end

    return str
end

-- NormalizePath attempts to find the parent of a directory but in terms of
-- responsibility. This is useful when we want to know processes that
-- attempt to modify directories outside of their scope. i.g:
-- c:\\program files\\google\\sdk\\list.py  ==> c:\\program files\\google\\
-- Any process which modifies files outside its scope it considered suspicious.
-- @param str string: The subject file path.
-- @return string: The normalized file path in success, or nil otherwise.
function utils.NormalizePath(filePath)
    -- Lower case the file path for easy pattern matching.
    filePath = filePath:lower()

    -- "Program Files" and "Program Files (x86) can use the shorter version,
    -- that is "progra~1" and "progra~2" correspondingly.
    filePath = filePath:gsub('progra~1', 'program files')
    filePath = filePath:gsub('progra~2', 'program files (x86)')

    -- If the file path does not start with a drive letter, abort.
    local match = filePath:match('^%a:\\')
    if match == nil then
        return nil
    end

    local match = filePath:match('^%a:\\programdata\\.-\\')
    if match ~= nil then
        return match
    end

    match = filePath:match('^%a:\\program files\\.-\\')
    if match ~= nil then
        return match
    end

    match = filePath:match('^%a:\\program files %(x86%)\\.-\\')
    if match ~= nil then
        return match
    end

    match = filePath:match('^%a:\\.-\\')
    if match ~= nil then
        return match
    end

    match = filePath:match('(.*[/\\])')
    if match ~= nil then
        return match
    end
    return nil
end

-- Check if a file extension is typically used by Microsoft Office, the first
-- two characters of the filename will be checked to determine if this may be
-- an Office lock file and will not be subjected to a header magic byte check.
-- @param extension string: The subject extension name.
-- @param fileName string: The subject file name.
-- @return boolean: True when an MS Office lock file is found. False otherwise.
function utils.IsOfficeLockFile(extension, fileName)

    -- A list of known Microsoft Office Extensions.
    local officeExtensions = {
        'doc',
        'docb',
        'docm',
        'docx',
        'dotm',
        'dotx',
        'dot',
        'wbk',
        'pot',
        'potm',
        'potx',
        'ppam',
        'pps',
        'ppsm',
        'ppsx',
        'ppt',
        'pptm',
        'pptx',
        'sldm',
        'sldx',
        'xla',
        'xlam',
        'xll',
        'xlm',
        'xls',
        'xlsb',
        'xlsm',
        'xlsx',
        'xlt',
        'xltm',
        'xltx',
        'xlw'
    }

    if utils.TableHasValue(officeExtensions, extension) then
        local index = string.find(fileName, '~$', nil, true)
        if index ~= nil then
            if index == 1 then
                return true
            end
        end
    end

    return false
end

-- Prints out tables summarizing process event activity sorted by operations and
-- extensions.
-- @param processData table: A table containing process data.
-- @return void.
function utils.PrintExtensionTables(processData)
    utils.DebugLog('=================')
    utils.DebugLog('Create Extensions')
    for k, v in pairs(processData.createExtensions) do
        utils.DebugLog('*** ' .. k)
        for _, v2 in pairs(v) do
            utils.DebugLog(v2.operation .. ' | ' .. string.sub(v2.entropy, 1, 4) .. ' | ' .. v2.alertScore .. ' | ' ..
                               string.sub(v2.filePath, 1, 200))
        end
    end
    utils.DebugLog('=================')
    utils.DebugLog('Modify Extensions')
    for k, v in pairs(processData.modifyExtensions) do
        utils.DebugLog('*** ' .. k)
        for _, v2 in pairs(v) do
            utils.DebugLog(v2.operation .. ' | ' .. string.sub(v2.entropy, 1, 4) .. ' | ' .. v2.alertScore .. ' | ' ..
                               string.sub(v2.filePath, 1, 200))
        end
    end
    utils.DebugLog('=================')
    utils.DebugLog('Delete Extensions')
    for k, v in pairs(processData.deleteExtensions) do
        utils.DebugLog('*** ' .. k)
        for _, v2 in pairs(v) do
            utils.DebugLog(v2.operation .. ' | ' .. string.sub(v2.entropy, 1, 4) .. ' | ' .. v2.alertScore .. ' | ' ..
                               string.sub(v2.filePath, 1, 200))
        end
    end
    utils.DebugLog('=================')
    utils.DebugLog('Rename Extensions')
    for k, v in pairs(processData.renameExtensions) do
        utils.DebugLog('*** ' .. k)
        for _, v2 in pairs(v) do
            utils.DebugLog(v2.operation .. ' | ' .. string.sub(v2.entropy, 1, 4) .. ' | ' .. v2.alertScore .. ' | ' ..
                               string.sub(v2.filePath, 1, 200))
        end
    end
    utils.DebugLog('=================')
    utils.DebugLog('Overwrite Extensions')
    for k, v in pairs(processData.overwriteExtensions) do
        utils.DebugLog('*** ' .. k)
        for _, v2 in pairs(v) do
            utils.DebugLog(v2.operation .. ' | ' .. string.sub(v2.entropy, 1, 4) .. ' | ' .. v2.alertScore .. ' | ' ..
                               string.sub(v2.filePath, 1, 200))
        end
    end

    utils.DebugLog('=================')
    utils.DebugLog('headerMismatchExtensions')
    for k, v in pairs(processData.headerMismatchExtensions) do
        utils.DebugLog('*** ' .. k)
    end

    utils.DebugLog('=================')
    utils.DebugLog('entropyMismatchExtensions')
    for k, v in pairs(processData.entropyMismatchExtensions) do
        utils.DebugLog('*** ' .. k .. ' : ' .. v)
    end
end

-- Provides a quick string summary of a process activity by tallying the different
-- types of file operations.
-- @param processData table: A table containing process data.
-- @return void.
function utils.PrintOperationTables(processData)
    local creates = 0
    local modifies = 0
    local deletes = 0
    local renames = 0
    local overwrites = 0

    for _, v in pairs(processData.createExtensions) do
        creates = creates + #v
    end

    for _, v in pairs(processData.modifyExtensions) do
        for _, _ in pairs(v) do
            modifies = modifies + 1
        end
    end

    for _, v in pairs(processData.deleteExtensions) do
        deletes = deletes + #v
    end

    for _, v in pairs(processData.renameExtensions) do
        renames = renames + #v
    end

    for _, v in pairs(processData.overwriteExtensions) do
        overwrites = overwrites + #v
    end

    local operationString =
        'PID: ' .. processData.processId .. ' Creates: ' .. creates .. ' | Modifies: ' .. modifies .. ' | Deletes: ' ..
            deletes .. ' | Renames: ' .. renames .. ' | Overwrites: ' .. overwrites
    return operationString
end

-- Prints a lua table. This function supports printing nested tables.
-- @param t Table: The table subject for printing.
-- @return: void.
function utils.PrintTable(t)
    local printTable_cache = {}

    local function sub_printTable(t, indent)

        if (printTable_cache[tostring(t)]) then
            utils.DebugLog(indent .. '*' .. tostring(t))
        else
            printTable_cache[tostring(t)] = true
            if (type(t) == 'table') then
                for pos, val in pairs(t) do
                    if (type(val) == 'table') then
                        utils.DebugLog(indent .. '[' .. pos .. '] => ' .. tostring(t) .. ' {')
                        sub_printTable(val, indent .. string.rep(' ', string.len(pos) + 8))
                        utils.DebugLog(indent .. string.rep(' ', string.len(pos) + 6) .. '}')
                    elseif (type(val) == 'string') then
                        utils.DebugLog(indent .. '[' .. pos .. '] => "' .. val .. '"')
                    else
                        utils.DebugLog(indent .. '[' .. pos .. '] => ' .. tostring(val))
                    end
                end
            else
                utils.DebugLog(indent .. tostring(t))
            end
        end
    end

    if (type(t) == 'table') then
        utils.DebugLog(tostring(t) .. ' {')
        sub_printTable(t, '  ')
        utils.DebugLog('}')
    else
        sub_printTable(t, '  ')
    end
end

------------------------------------------------------------------------------
-- The functions below are wrappers over functions that are called directly by
-- the sensor, when the lua module is used outside of the endpoint, the `mock`
-- module implements the required functions to mock.
------------------------------------------------------------------

-- Wrapper function around llog.
-- @param str string: The subject file path.
-- @return void.
function utils.DebugLog(str)
    -- TODO decouple logging.
    if globals.logging then
        -- llog(globals.namespace.nameString .. ': ' .. str)
        llog(str)
    end
end

-- Get the list of all user profiles.
-- @return table: A table representing the list of user profiles.
function utils.GetAllUserProfiles()
    local results = {}

    -- FOLDERID_UserProfiles.
    local usersDir = GetKnownFolderPath('{0762D272-C50A-4BB0-A382-697DCD729B80}')
    local users = ListDir(usersDir)

    for _, f in ipairs(users) do
        if f.Type == 'DIR' then
            table.insert(results, f.Path)
        end
    end
    return results
end

-- Determines what product is in use.
-- @return string: a string representing the current product: elastic or endgame.
function utils.GetProduct()
    -- check if we can resolve lproduct() func.
    if lproduct ~= nil then
        -- Check which product is in use.
        return lproduct()
    else
        -- lproduct will be nil *only* if we are running an endgame sensor.
        return 'endgame'
    end
end

-- Check if the actual sensor version is less than the provided version string.
-- @param targetVersion string: The targeted version.
-- @return boolean: True or false for properly formatted strings (ex. major.minor.release),
-- or false on formatting errors,
-- or true if lversion is nil.
function utils.CurrentVersionLessThan(targetVersion)
    if not utils.IsVersionAvailable() then
        return true
    end

    local currentVersion = lversion('sensor')

    -- Validate parameters.
    if (not currentVersion) or (not targetVersion) then
        return false
    end

    -- Grab the pieces.
    local currentMajor, currentMinor, currentRelease
    local targetMajor, targetMinor, targetRelease
    _, _, currentMajor, currentMinor, currentRelease = string.find(currentVersion, '(%d+)%.(%d+)%.(%d+)')
    _, _, targetMajor, targetMinor, targetRelease = string.find(targetVersion, '(%d+)%.(%d+)%.(%d+)')

    -- Validate major version parsing.
    if (not currentMajor) or (not targetMajor) then
        return false
    end

    -- Compare major versions.
    if (currentMajor < targetMajor) then
        return true
    end

    if (currentMajor == targetMajor) then

        -- Validate minor version parsing.
        if (not currentMinor) or (not targetMinor) then
            return false
        end

        -- Compare minor versions.
        if (currentMinor < targetMinor) then
            return true
        end

        if (currentMinor == targetMinor) then

            -- Validate release version parsing.
            if (not currentRelease) or (not targetRelease) then
                return false
            end

            -- Compare release versions.
            if (currentRelease < targetRelease) then
                return true
            end
        end
    end

    return false

end

-- Determines if lversion function is available for use in lua. lversion will
-- be nil only if we are running sensor version 3.53 or lower.
-- @return boolean: True if lversion is nil. False otherwise.
function utils.IsVersionAvailable()
    if lversion ~= nil then
        return true
    else
        return false
    end
end


local alert = {
    -- Limits the number of diagnostic alerts generated.
    DIAGNOSTIC_ALERT_CAP = 10,

    -- Mapping between file operations and their string representation.
    FILE_OP_STR_MAP = {'creation', 'modification', 'deletion', 'rename', 'overwrite', 'open'}

}

-- Inserts the input alert metric into the list of event data alert metrics.
-- @param eventData table: A table containing event data.
-- @param alertMetric string: The subject alert name.
-- @return table: A table representing the new event data alert metrics.
function alert.RaiseFileAlertMetric(eventData, alertMetric)
    if not utils.TableHasKey(eventData.alertMetrics, alertMetric) then
        table.insert(eventData.alertMetrics, alertMetric)
    end

    return eventData.alertMetrics
end

-- Handle alert generation by passing a table to the sensor callback via `lemit`.
-- @param alertProcessData table: A table containing alert process data.
-- @param isDiagnostic boolean: A boolean that indicates whether or not this is
-- a designated diagnostic alert.
-- @return boolean: True in every case. TODO: fix possible return values.
function alert.GenerateAlert(alertProcessData, isDiagnostic)
    local processTable = {}
    local product = utils.GetProduct()
    if product == nil or product == '' then
        -- GetProduct() will return "endgame" if import isn't found and
        -- lproduct() will always return a value, so if this is the case we're
        -- in undefined behavior territory and should bail.
        utils.DebugLog('Error collecting product information via GetProduct()')
        return true
    end

    if isDiagnostic and globals.namespace.totalAlerts >= alert.DIAGNOSTIC_ALERT_CAP then
        -- globals.alertGenerated = true
        utils.DebugLog('alert.DIAGNOSTIC_ALERT_CAP REACHED! alert will not be generated for PID: ' ..
                           alertProcessData.processId)
        return true
    end

    if isDiagnostic and alertProcessData.diagnosticAlertQueued then
        utils.DebugLog('FINALLY generate our DIAGNOSTIC alert!')
        -- set boolean to false to avoid duplicate diagnostic alerts
        alertProcessData.diagnosticAlertQueued = false
    elseif isDiagnostic and alertProcessData.diagnosticAlerted then
        utils.DebugLog('PREVIOUSLY DIAGNOSTIC ALERTED ON THIS PROCESS!')
        return true
    elseif false == alertProcessData.activeAnalysis then
        utils.DebugLog('Process no longer subject to active analysis')
        return true
    elseif true == alertProcessData.alerted then
        utils.DebugLog('Previously alerted on this process in this namespace')
        return true
    end

    if nil ~= alertProcessData.createExtensions then
        utils.PrintExtensionTables(alertProcessData)
        utils.PrintOperationTables(alertProcessData)
    end

    -- Set fields shared between endgame and elastic.
    processTable.pid = alertProcessData.processId
    processTable.is_alert = true
    processTable.score = alertProcessData.totalScore
    processTable.alert_files = {}

    if isDiagnostic then
        utils.DebugLog('DIAGNOSTIC ALERT: ' .. alertProcessData.processId)
        alertProcessData.diagnosticAlerted = true
        -- Endpoint/sensor still use 'beta_alert' key.
        processTable.beta_alert = true
    else
        alertProcessData.activeAnalysis = false
        alertProcessData.alerted = true
        -- Endpoint/sensor still use 'beta_alert' key.
        processTable.beta_alert = false
    end

    -- Emit alert in specific schema for corresponding product in use.
    if product == 'endgame' then
        alert.GenerateEndgameAlert(processTable, alertProcessData)
    elseif product == 'elastic' then
        processTable.canary_alert = alertProcessData.canary_alert

        -- Add in RansomwareChildProcesses if present.
        if nil ~= alertProcessData.child_processes then
            processTable.child_processes = alertProcessData.child_processes
        end

        alert.GenerateElasticAlert(processTable, alertProcessData)
    end

    lemit(processTable)
    globals.alertGenerated = true
    globals.namespace.totalAlerts = globals.namespace.totalAlerts + 1
    utils.DebugLog('namespace.totalAlerts: ' .. globals.namespace.totalAlerts)
    return true
end

-- Generate an alert in the old Endgame schema.
-- @param processData table: A table containing process data.
-- @param alertProcessData table: A table containing alert process data.
-- @return void.
function alert.GenerateEndgameAlert(processTable, alertProcessData)
    local tempMessage = {}
    local incompatible = false

    -- Set Endgame specific fields.
    processTable.file_list = {}
    processTable.process_alerts = {'PROCESS_LUA_ALERT'}

    -- Check compatibility.
    incompatible = utils.CurrentVersionLessThan('3.54.0')

    for _, v in pairs(alertProcessData.events) do
        tempMessage = {}
        tempMessage.file_path = v.filePath

        if not incompatible then
            -- 3.54 and greater sensors are compatible with new changes;
            -- schema changes and proper use of alert_files messages for extended
            -- alert data needed for triage and event trace replay.
            table.insert(processTable.file_list, tempMessage)

            tempMessage = {}
            tempMessage.file_path = v.filePath
            tempMessage.score = v.alertScore
            tempMessage.entropy = v.entropy
            tempMessage.file_extension = v.fileExtension
            tempMessage.bk_file_operation = v.operation
            tempMessage.file_alerts = {}
            tempMessage.header_string = v.headerString

            for _, v2 in pairs(v.alertMetrics) do
                table.insert(tempMessage.file_alerts, v2)
            end

            if utils.FILE_RENAME == v.operation then
                tempMessage.file_previous_path = v.filePreviousPath
                tempMessage.file_previous_extension = v.filePreviousExtension
            end

            table.insert(processTable.alert_files, tempMessage)

        elseif incompatible then
            -- Maintain clean filepath entries for 3.53.
            table.insert(processTable.file_list, tempMessage)
        end
    end

    -- Hacky version left in to support sending extended triage data for
    -- 3.53 (since we didn't parse alert_files entries in the sensor).
    if incompatible then
        for _, v in pairs(alertProcessData.events) do
            tempMessage = {}
            tempMessage.file_path = v.fileName .. ' | ' .. v.alertScore .. ' | ' .. v.entropy .. ' | ' .. v.headerString
            table.insert(processTable.file_list, tempMessage)
        end

        for _, v in pairs(alertProcessData.events) do
            tempMessage = {}
            tempMessage.file_path = v.fileName

            for _, v2 in pairs(v.alertMetrics) do
                tempMessage.file_path = tempMessage.file_path .. '|' .. v2
            end

            tempMessage.file_path = tempMessage.file_path .. ' | ' .. v.operation + .0

            if utils.FILE_RENAME == v.operation then
                tempMessage.file_path = tempMessage.file_path .. ' | ' .. v.filePreviousPath
            end

            table.insert(processTable.file_list, tempMessage)
        end
    end
end

-- Generates an alert in elastic ECS schema.
-- @param processData table: A table containing process data.
-- @param alertProcessData table: A table containing alert process data.
-- @return void.
function alert.GenerateElasticAlert(processTable, alertProcessData)
    local tempMessage = {}
    for _, v in pairs(alertProcessData.events) do
        -- Output data in ECS Schema format
        -- files :
        --     fields :
        --         operation :
        --         entropy :
        --         metrics :
        --         extension :
        --         original.path :
        --         original.extension :
        --         path :
        --         data :
        --         score :
        tempMessage = {}
        tempMessage.path = v.filePath
        tempMessage.score = v.alertScore
        tempMessage.entropy = v.entropy
        tempMessage.extension = v.fileExtension
        tempMessage.data = v.headerString

        -- Lua arrays start from 1 so add 1 to correctly index the specified
        -- file operation to string.
        if nil ~= alert.FILE_OP_STR_MAP[v.operation + 1] then
            tempMessage.operation = alert.FILE_OP_STR_MAP[v.operation + 1]
        end

        local metricsCount = 0

        for _, v2 in pairs(v.alertMetrics) do
            if 0 == metricsCount then
                tempMessage.metrics = {}
            end

            table.insert(tempMessage.metrics, v2)
            metricsCount = metricsCount + 1
        end

        if utils.FILE_RENAME == v.operation then
            tempMessage.original = {}
            tempMessage.original['path'] = v.filePreviousPath
            tempMessage.original['extension'] = v.filePreviousExtension
        end

        -- As the endpoint doesn't parse alert_files (but rather pulls the
        -- array out by the key) we can leave this the same and re-append
        -- as new ECS `files` field in the endpoint.
        table.insert(processTable.alert_files, tempMessage)
    end
end


_G.globals = {}
globals.logging = false
globals.alertGenerated = false
globals.namespaces = {}
globals.config = {}

-- should always start as false
globals.diagnosticCanariesDropped = false
globals.productionCanariesDropped = false
globals.diagnosticStartupInvoked = false
globals.productionStartupInvoked = false

-- is this running on elastic 8.6.0 or newer?
globals.canaryCompatible = false

-- limit canary cleanup failure alerts
globals.bCanaryDiagnosticsEmitted = false

-- namespace is used to reference the current namespace while we are in the globals scope.
globals.namespace = nil

-- default metric values.
globals.config["ABNORMAL_EXTENSION_CHARACTERS"] = {}
globals.config["ABNORMAL_EXTENSION_CHARACTERS"]["score"] = 0.1
globals.config["CREATE_EXTENSION_KNOWN_HEADER_MISMATCH_WITH_PREVIOUSLY_DELETED_SUBSTRING"] = {}
globals.config["CREATE_EXTENSION_KNOWN_HEADER_MISMATCH_WITH_PREVIOUSLY_DELETED_SUBSTRING"]["score"] = 1.0
globals.config["CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN"] = {}
globals.config["CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN"]["score"] = 0.002
globals.config["CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED"] = {}
globals.config["CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED"]["score"] = 0.02
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN"] = {}
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN"]["score"] = 0.005
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED"] = {}
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED"]["score"] = 0.03
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_AVERAGE"] = {}
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_AVERAGE"]["score"] = 0.1
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGH"] = {}
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGH"]["score"] = 0.15
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHER"] = {}
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHER"]["score"] = 0.2
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHEST"] = {}
globals.config["CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHEST"]["score"] = 0.5
globals.config["CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGH"] = {}
globals.config["CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGH"]["score"] = 0.05
globals.config["CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHER"] = {}
globals.config["CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHER"]["score"] = 0.15
globals.config["CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHEST"] = {}
globals.config["CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHEST"]["score"] = 0.25
globals.config["DELETE_EXTENSION_BLOCKLIST_PREVIOUSLY_CREATED_FILEPATH"] = {}
globals.config["DELETE_EXTENSION_BLOCKLIST_PREVIOUSLY_CREATED_FILEPATH"]["score"] = 0.75
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGH"] = {}
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGH"]["score"] = 0.4
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHER"] = {}
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHER"]["score"] = 0.5
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHEST"] = {}
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHEST"]["score"] = 0.6
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH"] = {}
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH"]["score"] = 0.3
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER"] = {}
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER"]["score"] = 0.4
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST"] = {}
globals.config["DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST"]["score"] = 0.5
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH"]["score"] = 0.3
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER"]["score"] = 0.4
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST"]["score"] = 0.5
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING"]["score"] = 0.1
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGH"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGH"]["score"] = 0.2
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHER"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHER"]["score"] = 0.3
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHEST"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHEST"]["score"] = 0.4
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN"] = {}
globals.config["DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN"]["score"] = 0.1
globals.config["ENTROPY_HIGHER"] = {}
globals.config["ENTROPY_HIGHER"]["score"] = 0.05
globals.config["ENTROPY_HIGHER_EXTENSION_UNKNOWN"] = {}
globals.config["ENTROPY_HIGHER_EXTENSION_UNKNOWN"]["score"] = 0.05
globals.config["ENTROPY_MISMATCH_HIGHER"] = {}
globals.config["ENTROPY_MISMATCH_HIGHER"]["score"] = 0.5
globals.config["ENTROPY_MISMATCH_HIGHER_WITH_HEADER_MISMATCH"] = {}
globals.config["ENTROPY_MISMATCH_HIGHER_WITH_HEADER_MISMATCH"]["score"] = 0.5
globals.config["ENTROPY_MISMATCH_HIGHEST"] = {}
globals.config["ENTROPY_MISMATCH_HIGHEST"]["score"] = 0.75
globals.config["ENTROPY_MISMATCH_HIGHEST_WITH_HEADER_MISMATCH"] = {}
globals.config["ENTROPY_MISMATCH_HIGHEST_WITH_HEADER_MISMATCH"]["score"] = 1.0
globals.config["EXTENSION_BLOCKLIST"] = {}
globals.config["EXTENSION_BLOCKLIST"]["score"] = 0.4
globals.config["HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET"] = {}
globals.config["HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET"]["score"] = 0.3
globals.config["PREVIOUS_HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET"] = {}
globals.config["PREVIOUS_HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET"]["score"] = 0.2
globals.config["RENAME_ENTROPY_MISMATCH_HIGHER"] = {}
globals.config["RENAME_ENTROPY_MISMATCH_HIGHER"]["score"] = 0.3
globals.config["RENAME_ENTROPY_MISMATCH_HIGHEST"] = {}
globals.config["RENAME_ENTROPY_MISMATCH_HIGHEST"]["score"] = 0.4
globals.config["RENAME_EXTENSION_KNOWN_TO_BLANK"] = {}
globals.config["RENAME_EXTENSION_KNOWN_TO_BLANK"]["score"] = 0.002
globals.config["RENAME_EXTENSION_KNOWN_TO_BLOCKLIST"] = {}
globals.config["RENAME_EXTENSION_KNOWN_TO_BLOCKLIST"]["score"] = 0.4
globals.config["RENAME_EXTENSION_KNOWN_TO_UNKNOWN"] = {}
globals.config["RENAME_EXTENSION_KNOWN_TO_UNKNOWN"]["score"] = 0.0025
globals.config["RENAME_EXTENSION_KNOWN_TO_UNKNOWN_MULTIPLE"] = {}
globals.config["RENAME_EXTENSION_KNOWN_TO_UNKNOWN_MULTIPLE"]["score"] = 0.005
globals.config["RENAME_EXTENSION_UNKNOWN_TO_BLOCKLIST"] = {}
globals.config["RENAME_EXTENSION_UNKNOWN_TO_BLOCKLIST"]["score"] = 0.3
globals.config["RENAME_EXTENSION_UNKNOWN_TO_UNKNOWN"] = {}
globals.config["RENAME_EXTENSION_UNKNOWN_TO_UNKNOWN"]["score"] = 0.01
globals.config["SUBEXTENSION_KNOWN"] = {}
globals.config["SUBEXTENSION_KNOWN"]["score"] = 0.003
globals.config["SUBEXTENSION_KNOWN_EXTENSION_UNKNOWN"] = {}
globals.config["SUBEXTENSION_KNOWN_EXTENSION_UNKNOWN"]["score"] = 0.0015
globals.config["SUBEXTENSION_UNKNOWN_AND_PREVIOUSLY_DELETED"] = {}
globals.config["SUBEXTENSION_UNKNOWN_AND_PREVIOUSLY_DELETED"]["score"] = 0.005
globals.config["TREND_SCORE_DELETE_CREATE_RATIO"] = {}
globals.config["TREND_SCORE_DELETE_CREATE_RATIO"]["score"] = 0.01
globals.config["TREND_SCORE_MORE_CREATES_THAN_DELETES"] = {}
globals.config["TREND_SCORE_MORE_CREATES_THAN_DELETES"]["score"] = 2.0
globals.config["TREND_SCORE_RENAME_EXTENSION_RATIO"] = {}
globals.config["TREND_SCORE_RENAME_EXTENSION_RATIO"]["score"] = 0.01
globals.config["TREND_SCORE_NUM_RENAMES"] = {}
globals.config["TREND_SCORE_NUM_RENAMES"]["score"] = 0.01
globals.config["TREND_SCORE_SINGLE_PREV_RENAME_EXTENSION"] = {}
globals.config["TREND_SCORE_SINGLE_PREV_RENAME_EXTENSION"]["score"] = 0.01

globals.INVALID_PROCESS_ID = 1

globals.PROCESS_EVENT_THRESHOLD = 200
globals.PROCESS_EXTENDED_EVENT_THRESHOLD = 400
globals.PROCESS_FINAL_EXTENDED_EVENT_THRESHOLD = 650
globals.PROCESS_TREND_FLOOR = 50
globals.PROCESS_ALERT_SCORE_THRESHOLD = 30.0
globals.PROCESS_PARENT_CHILD_ALERT_SCORE_THRESHOLD = 100.0

-- limits the number of diagnostic alerts generated
globals.DIAGNOSTIC_ALERT_CAP = 10
globals.CANARY_CREATE_FILE_ALERT_CAP = 5
globals.MAX_CHILD_PROCESSES = 5

-- TODO: refactor these RENAME globals to be paired with equivalent string mapping
globals.DEFAULT_RENAME = 0
globals.KNOWN_TO_SUSPICIOUS = 1
globals.KNOWN_TO_UNKNOWN = 2
globals.KNOWN_TO_BLANK = 3
globals.UNKNOWN_TO_SUSPICIOUS = 4
globals.UNKNOWN_TO_UNKNOWN = 5

globals.ENTROPY_REALLY_HIGH = 7.9
globals.ENTROPY_VERY_HIGH = 7.5
globals.ENTROPY_HIGH = 7.0

globals.FILE_CREATE_NEW = 0
globals.FILE_MODIFY = 1
globals.FILE_DELETE = 2
globals.FILE_RENAME = 3
globals.FILE_OVERWRITE = 4
globals.FILE_OPEN = 5

globals.fileOperationStringMappings = {'creation', 'modification', 'deletion', 'rename', 'overwrite', 'open'}

-- TODO: refactor the ENTROPY_STATUS_* globals along with string mapping like seen below
-- TODO x 2: refactor the parallel variables between these entries and
--           ENTROPY_REALLY_HIGH, ENTROPY_VERY_HIGH, ENTROPY_HIGH to avoid code
--           duplication and simplify code maintenance

-- globals.ENTROPY_STATUS_DEFAULT = 0
-- globals.ENTROPY_STATUS_HIGH = 1
-- globals.ENTROPY_STATUS_VERY_HIGH = 2
-- globals.ENTROPY_STATUS_REALLY_HIGH = 3
-- globals.ENTROPY_STATUS_MISMATCH_VERY_HIGH = 4
-- globals.ENTROPY_STATUS_MISMATCH_REALLY_HIGH = 5
--
-- globals.ENTROPY_STATUS_TO_STRING = {
--   [globals.ENTROPY_STATUS_DEFAULT]='ENTROPY_DEFAULT',
--   [globals.ENTROPY_STATUS_HIGH]='ENTROPY_HIGH',
--   [globals.ENTROPY_STATUS_VERY_HIGH]='ENTROPY_VERY_HIGH',
--   [globals.ENTROPY_STATUS_REALLY_HIGH]='ENTROPY_REALLY_HIGH',
--   [globals.ENTROPY_STATUS_MISMATCH_VERY_HIGH]='ENTROPY_MISMATCH_VERY_HIGH',
--   [globals.ENTROPY_STATUS_MISMATCH_REALLY_HIGH]='ENTROPY_MISMATCH_REALLY_HIGH',
-- }

globals.HEADER_MISMATCH_THRESHOLD = 5
globals.ENTROPY_MISMATCH_THRESHOLD = 5

globals.ENTROPY_STATUS_DEFAULT = 0
globals.ENTROPY_STATUS_HIGH = 1
globals.ENTROPY_STATUS_VERY_HIGH = 2
globals.ENTROPY_STATUS_REALLY_HIGH = 3
globals.ENTROPY_STATUS_MISMATCH_VERY_HIGH = 4
globals.ENTROPY_STATUS_MISMATCH_REALLY_HIGH = 5

-- table of file paths to ignore when processing file events.
globals.regexIgnorePaths = {
    '^[a-z]:\\\\users\\\\.*\\\\appdata\\\\',
    '^[a-z]:\\\\users\\\\.*\\\\downloads\\\\',
    '^[a-z]:\\\\windows\\\\logs\\\\',
    '^[a-z]:\\\\windows\\\\ccm\\\\',
    '^[a-z]:\\\\windows\\\\csc\\\\',
    '^[a-z]:\\\\windows\\\\ccmcache\\\\',
    '^[a-z]:\\\\windows\\\\temp\\\\',
    '^[a-z]:\\\\windows\\\\softwaredistribution\\\\',
    '^[a-z]:\\\\windows\\\\prefetch\\\\',
    '^[a-z]:\\\\windows\\\\installer\\\\',
    '^[a-z]:\\\\windows\\\\rescache\\\\',
    '^[a-z]:\\\\windows\\\\winsxs\\\\',
    '^[a-z]:\\\\windows\\\\appcompat\\\\',
    '^[a-z]:\\\\windows\\\\system32\\\\logfiles\\\\',
    '^[a-z]:\\\\windows\\\\system32\\\\spp\\\\',
    '^[a-z]:\\\\windows\\\\system32\\\\wdi\\\\',
    '^[a-z]:\\\\windows\\\\system32\\\\winevt\\\\',
    '^[a-z]:\\\\windows\\\\sys.*\\\\config\\\\systemprofile\\\\appdata\\\\',
    '^[a-z]:\\\\programdata\\\\',
    '^[a-z]:\\\\msocache\\\\',
    '^[a-z]:\\\\ccmcache\\\\',
    '^[a-z]:\\\\[$]windows[.]~bt\\\\',
    '^[a-z]:\\\\[$]upgrade[.]~os\\\\',
    '^[a-z]:\\\\sccmcontentlib\\\\',
    '^[a-z]:\\\\sms_dp[$]\\\\',
    '^[a-z]:\\\\program files\\\\steam\\\\',
    '^[a-z]:\\\\program files \\(x86\\)\\\\steam\\\\',
    '^[a-z]:\\\\program files\\\\microsoft configuration manager\\\\',
    '^[a-z]:\\\\system volume information\\\\',
    '^[a-z]:\\\\system recovery\\\\',
    '^[a-z]:\\\\program files\\\\microsoft office servers\\\\.*\\\\data\\\\office ',
    '^[a-z]:\\\\program files\\\\microsoft\\\\exchange ',
    '^[a-z]:\\\\windows\\\\servic',
    '^[a-z]:\\\\program files\\(x86\\)\\\\skf\\\\surveryor\\\\',
    '^[a-z]:\\\\windows\\\\system32\\\\spool\\\\drivers\\\\',
    '^[a-z]:\\\\dfsroots\\\\',
    '^[a-z]:\\\\lscc\\\\',
    '^[a-z]:\\\\_smstasksequence\\\\',
    '^[a-z]:\\\\mimecast\\\\mse\\\\',
    '.*\\\\!tdr.bin\\\\',
    '.*\\\\.dropbox.cache\\\\',
    '.*\\\\iis temporary compressed files\\\\',
    '.*\\\\appdata\\\\local\\\\google\\\\chrome\\\\user data\\\\',
    '.*\\\\microsoft sql server\\\\.*\\\\setup bootstrap\\\\update cache\\\\',
    '.*\\\\microsoft\\\\windows\\\\inetcache\\\\content.mso\\\\',
    '.*server\\\\applications\\\\gthrsvc\\\\',
    '.*server\\\\.*\\\\clientaccess\\\\oab\\\\temp\\\\',
}


-- table of known Microsoft Office Extensions
globals.officeExtensions = {
    'doc',
    'docb',
    'docm',
    'docx',
    'dotm',
    'dotx',
    'dot',
    'wbk',
    'pot',
    'potm',
    'potx',
    'ppam',
    'pps',
    'ppsm',
    'ppsx',
    'ppt',
    'pptm',
    'pptx',
    'sldm',
    'sldx',
    'xla',
    'xlam',
    'xll',
    'xlm',
    'xls',
    'xlsb',
    'xlsm',
    'xlsx',
    'xlt',
    'xltm',
    'xltx',
    'xlw'
}

globals.t_xml_1 = {0x3C, 0x3F, 0x78, 0x6D, 0x6C}
globals.t_null_1 = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

globals.extensionMap = {}
globals.extensionMap["ax"] = utils.ExtensionData(0, false, {})
globals.extensionMap["com"] = utils.ExtensionData(0, false, {{77,90,},})
globals.extensionMap["cpl"] = utils.ExtensionData(0, false, {})
globals.extensionMap["dll"] = utils.ExtensionData(0, false, {{77,90,},})
globals.extensionMap["drv"] = utils.ExtensionData(0, false, {{77,90,},})
globals.extensionMap["efi"] = utils.ExtensionData(0, false, {})
globals.extensionMap["exe"] = utils.ExtensionData(0, false, {{77,90,},})
globals.extensionMap["filepart"] = utils.ExtensionData(0, false, {})
globals.extensionMap["msi"] = utils.ExtensionData(0, false, {{208,207,17,224,161,177,26,225,},})
globals.extensionMap["ocx"] = utils.ExtensionData(0, false, {})
globals.extensionMap["opexdiag"] = utils.ExtensionData(0, false, {})
globals.extensionMap["scr"] = utils.ExtensionData(0, false, {})
globals.extensionMap["sys"] = utils.ExtensionData(0, false, {{77,90,},})
globals.extensionMap["001"] = utils.ExtensionData(0, true, {})
globals.extensionMap["002"] = utils.ExtensionData(0, true, {})
globals.extensionMap["003"] = utils.ExtensionData(0, true, {})
globals.extensionMap["automaticdestinations-ms"] = utils.ExtensionData(0, true, {})
globals.extensionMap["bcf"] = utils.ExtensionData(0, true, {})
globals.extensionMap["blf"] = utils.ExtensionData(0, true, {})
globals.extensionMap["cache"] = utils.ExtensionData(0, true, {})
globals.extensionMap["check_cache"] = utils.ExtensionData(0, true, {})
globals.extensionMap["chk"] = utils.ExtensionData(0, true, {})
globals.extensionMap["ci"] = utils.ExtensionData(0, true, {})
globals.extensionMap["cmake"] = utils.ExtensionData(0, true, {})
globals.extensionMap["cmdline"] = utils.ExtensionData(0, true, {})
globals.extensionMap["crwl"] = utils.ExtensionData(0, true, {})
globals.extensionMap["customdestinations-ms"] = utils.ExtensionData(0, true, {})
globals.extensionMap["cvr"] = utils.ExtensionData(0, true, {})
globals.extensionMap["dblog"] = utils.ExtensionData(0, true, {})
globals.extensionMap["dbtmp"] = utils.ExtensionData(0, true, {})
globals.extensionMap["depend"] = utils.ExtensionData(0, true, {})
globals.extensionMap["diagpkg"] = utils.ExtensionData(0, true, {})
globals.extensionMap["diagsession"] = utils.ExtensionData(0, true, {})
globals.extensionMap["dir"] = utils.ExtensionData(0, true, {})
globals.extensionMap["etl"] = utils.ExtensionData(0, true, {})
globals.extensionMap["evtx"] = utils.ExtensionData(0, true, {})
globals.extensionMap["exp"] = utils.ExtensionData(0, true, {})
globals.extensionMap["filters"] = utils.ExtensionData(0, true, {})
globals.extensionMap["gthr"] = utils.ExtensionData(0, true, {})
globals.extensionMap["hit"] = utils.ExtensionData(0, true, {})
globals.extensionMap["ico"] = utils.ExtensionData(0, true, {})
globals.extensionMap["ilk"] = utils.ExtensionData(0, true, {})
globals.extensionMap["lastbuildstate"] = utils.ExtensionData(0, true, {})
globals.extensionMap["library-ms"] = utils.ExtensionData(0, true, {})
globals.extensionMap["list"] = utils.ExtensionData(0, true, {})
globals.extensionMap["little"] = utils.ExtensionData(0, true, {})
globals.extensionMap["log1"] = utils.ExtensionData(0, true, {})
globals.extensionMap["mui"] = utils.ExtensionData(0, true, {})
globals.extensionMap["nls"] = utils.ExtensionData(0, true, {})
globals.extensionMap["obj"] = utils.ExtensionData(0, true, {})
globals.extensionMap["perlcriticrc"] = utils.ExtensionData(0, true, {})
globals.extensionMap["pset"] = utils.ExtensionData(0, true, {})
globals.extensionMap["regtrans-ms"] = utils.ExtensionData(0, true, {})
globals.extensionMap["rsp"] = utils.ExtensionData(0, true, {})
globals.extensionMap["sbstore"] = utils.ExtensionData(0, true, {})
globals.extensionMap["sqlite"] = utils.ExtensionData(0, true, {})
globals.extensionMap["sqlite-shm"] = utils.ExtensionData(0, true, {})
globals.extensionMap["sqlite-wal"] = utils.ExtensionData(0, true, {})
globals.extensionMap["stamp"] = utils.ExtensionData(0, true, {})
globals.extensionMap["suodat"] = utils.ExtensionData(0, true, {})
globals.extensionMap["swp"] = utils.ExtensionData(0, true, {})
globals.extensionMap["temp"] = utils.ExtensionData(0, true, {})
globals.extensionMap["tlog"] = utils.ExtensionData(0, true, {})
globals.extensionMap["trn"] = utils.ExtensionData(0, true, {})
globals.extensionMap["unsuccessfulbuild"] = utils.ExtensionData(0, true, {})
globals.extensionMap["vcxproj"] = utils.ExtensionData(0, true, {})
globals.extensionMap["viminfo"] = utils.ExtensionData(0, true, {})
globals.extensionMap["wid"] = utils.ExtensionData(0, true, {})
globals.extensionMap["winprf"] = utils.ExtensionData(0, true, {})
globals.extensionMap["xlb"] = utils.ExtensionData(0, true, {})
globals.extensionMap["7z"] = utils.ExtensionData(1, false, {{55,122,188,175,39,28,},})
globals.extensionMap["accdb"] = utils.ExtensionData(1, false, {{},})
globals.extensionMap["ace"] = utils.ExtensionData(1, false, {})
globals.extensionMap["aiff"] = utils.ExtensionData(1, false, {{},})
globals.extensionMap["apk"] = utils.ExtensionData(1, false, {{80,75,},})
globals.extensionMap["asf"] = utils.ExtensionData(1, false, {{},})
globals.extensionMap["avi"] = utils.ExtensionData(1, false, {{},})
globals.extensionMap["bak"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bin"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bmp"] = utils.ExtensionData(1, false, {{66,77,},{71,73,70,56,},{255,216,255,},{239,191,189,239,},{137,80,78,71,13,10,},{137,80,78,71,13,10,26,10,},{71,73,70,56,57,97,},})
globals.extensionMap["bz2"] = utils.ExtensionData(1, false, {{66,90,104,},})
globals.extensionMap["cab"] = utils.ExtensionData(1, false, {{77,83,67,70,},{73,83,99,40,},})
globals.extensionMap["car"] = utils.ExtensionData(1, false, {})
globals.extensionMap["cfg"] = utils.ExtensionData(1, false, {})
globals.extensionMap["chm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["class"] = utils.ExtensionData(1, false, {{202,254,186,190,},})
globals.extensionMap["cr2"] = utils.ExtensionData(1, false, {{73,73,42,0,16,0,0,0,67,82,},})
globals.extensionMap["crt"] = utils.ExtensionData(1, false, {})
globals.extensionMap["crx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dar"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dat"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dazip"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dmg"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dmp"] = utils.ExtensionData(1, false, {})
globals.extensionMap["docm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["docx"] = utils.ExtensionData(1, false, {{80,75,},{7,},{10,},})
globals.extensionMap["dotm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dotx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["flac"] = utils.ExtensionData(1, false, {{102,76,97,67,},})
globals.extensionMap["flv"] = utils.ExtensionData(1, false, {})
globals.extensionMap["gif"] = utils.ExtensionData(1, false, {{66,77,},{71,73,70,56,},{255,216,255,},{239,191,189,239,},{137,80,78,71,13,10,},{137,80,78,71,13,10,26,10,},{71,73,70,56,57,97,},})
globals.extensionMap["gz"] = utils.ExtensionData(1, false, {{31,139,},})
globals.extensionMap["info"] = utils.ExtensionData(1, false, {})
globals.extensionMap["iso"] = utils.ExtensionData(1, false, {{67,68,48,48,49,},})
globals.extensionMap["jar"] = utils.ExtensionData(1, false, {{80,75,},})
globals.extensionMap["jpe"] = utils.ExtensionData(1, false, {})
globals.extensionMap["jpeg"] = utils.ExtensionData(1, false, {{66,77,},{71,73,70,56,},{255,216,255,},{239,191,189,239,},{137,80,78,71,13,10,},{137,80,78,71,13,10,26,10,},{71,73,70,56,57,97,},})
globals.extensionMap["jpg"] = utils.ExtensionData(1, false, {{66,77,},{71,73,70,56,},{255,216,255,},{239,191,189,239,},{137,80,78,71,13,10,},{137,80,78,71,13,10,26,10,},{71,73,70,56,57,97,},})
globals.extensionMap["jse"] = utils.ExtensionData(1, false, {})
globals.extensionMap["lz"] = utils.ExtensionData(1, false, {})
globals.extensionMap["lzma"] = utils.ExtensionData(1, false, {})
globals.extensionMap["lzo"] = utils.ExtensionData(1, false, {})
globals.extensionMap["m4a"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mar"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mka"] = utils.ExtensionData(1, false, {{26,69,223,163,},})
globals.extensionMap["mks"] = utils.ExtensionData(1, false, {{26,69,223,163,},})
globals.extensionMap["mkv"] = utils.ExtensionData(1, false, {{26,69,223,163,},})
globals.extensionMap["mov"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mp3"] = utils.ExtensionData(1, false, {{73,68,51,},{255,251,},})
globals.extensionMap["mp4"] = utils.ExtensionData(1, false, {})
globals.extensionMap["msp"] = utils.ExtensionData(1, false, {})
globals.extensionMap["odp"] = utils.ExtensionData(1, false, {{80,75,},})
globals.extensionMap["ods"] = utils.ExtensionData(1, false, {{80,75,},})
globals.extensionMap["odt"] = utils.ExtensionData(1, false, {{80,75,},})
globals.extensionMap["oga"] = utils.ExtensionData(1, false, {{79,103,103,83,},})
globals.extensionMap["ogg"] = utils.ExtensionData(1, false, {{79,103,103,83,},})
globals.extensionMap["ogv"] = utils.ExtensionData(1, false, {{79,103,103,83,},})
globals.extensionMap["part"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pdb"] = utils.ExtensionData(1, false, {{77,105,99,114,111,115,111,102,116,32,67,47,67,43,43,32,},{66,83,74,66,},})
globals.extensionMap["pdf"] = utils.ExtensionData(1, false, {{37,80,68,70,},})
globals.extensionMap["pkpass"] = utils.ExtensionData(1, false, {})
globals.extensionMap["png"] = utils.ExtensionData(1, false, {{66,77,},{71,73,70,56,},{255,216,255,},{239,191,189,239,},{137,80,78,71,13,10,},{137,80,78,71,13,10,26,10,},{71,73,70,56,57,97,},})
globals.extensionMap["pot"] = utils.ExtensionData(1, false, {})
globals.extensionMap["potm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["potx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ppa"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ppam"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pps"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ppsm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ppsx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pptm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pptx"] = utils.ExtensionData(1, false, {{80,75,},{7,},{10,},})
globals.extensionMap["ps"] = utils.ExtensionData(1, false, {})
globals.extensionMap["psd"] = utils.ExtensionData(1, false, {{56,66,80,83,},})
globals.extensionMap["pst"] = utils.ExtensionData(1, false, {{33,66,68,78,66,},})
globals.extensionMap["pyd"] = utils.ExtensionData(1, false, {{77,90,},})
globals.extensionMap["rar"] = utils.ExtensionData(1, false, {{82,97,114,33,26,7,0,},{82,97,114,33,26,7,1,0,},})
globals.extensionMap["rll"] = utils.ExtensionData(1, true, {{77,90,},})
globals.extensionMap["rz"] = utils.ExtensionData(1, false, {})
globals.extensionMap["swf"] = utils.ExtensionData(1, false, {{70,87,83,},{67,87,83,},})
globals.extensionMap["tar"] = utils.ExtensionData(1, false, {})
globals.extensionMap["tbl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["tbz2"] = utils.ExtensionData(1, false, {})
globals.extensionMap["tif"] = utils.ExtensionData(1, false, {{73,73,42,0,},{77,77,0,42,},})
globals.extensionMap["tiff"] = utils.ExtensionData(1, false, {{73,73,42,0,},{77,77,0,42,},})
globals.extensionMap["tlz"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vfs0"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vmdk"] = utils.ExtensionData(1, false, {{75,68,77,},})
globals.extensionMap["wallet"] = utils.ExtensionData(1, false, {{10,22,111,114,103,46,98,105,116,99,111,105,110,46,112,114,},})
globals.extensionMap["war"] = utils.ExtensionData(1, false, {})
globals.extensionMap["wav"] = utils.ExtensionData(1, false, {{82,},{87,},})
globals.extensionMap["webm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["wim"] = utils.ExtensionData(1, false, {})
globals.extensionMap["wma"] = utils.ExtensionData(1, false, {{48,38,178,117,142,102,207,17,166,217,0,170,0,98,206,108,},})
globals.extensionMap["wmo"] = utils.ExtensionData(1, false, {})
globals.extensionMap["wmv"] = utils.ExtensionData(1, false, {{48,38,178,117,142,102,207,17,166,217,0,170,0,98,206,108,},})
globals.extensionMap["woff"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xar"] = utils.ExtensionData(1, false, {{120,97,114,33,},})
globals.extensionMap["xla"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xlam"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xlsb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xlsm"] = utils.ExtensionData(1, false, {{80,75,},})
globals.extensionMap["xlsx"] = utils.ExtensionData(1, false, {{80,75,},{7,},{10,},})
globals.extensionMap["xlt"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xltx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xps"] = utils.ExtensionData(1, false, {})
globals.extensionMap["z"] = utils.ExtensionData(1, false, {})
globals.extensionMap["zip"] = utils.ExtensionData(1, false, {{80,75,},{31,139,},{120,},})
globals.extensionMap["zipx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["zz"] = utils.ExtensionData(1, false, {})
globals.extensionMap["acm"] = utils.ExtensionData(1, true, {})
globals.extensionMap["aml"] = utils.ExtensionData(1, true, {})
globals.extensionMap["ascii"] = utils.ExtensionData(1, true, {})
globals.extensionMap["asp"] = utils.ExtensionData(1, true, {})
globals.extensionMap["aspx"] = utils.ExtensionData(1, true, {})
globals.extensionMap["assoc"] = utils.ExtensionData(1, true, {})
globals.extensionMap["asx"] = utils.ExtensionData(1, true, {})
globals.extensionMap["bash_history"] = utils.ExtensionData(1, true, {})
globals.extensionMap["bash_profile"] = utils.ExtensionData(1, true, {})
globals.extensionMap["bashrc"] = utils.ExtensionData(1, true, {})
globals.extensionMap["bat"] = utils.ExtensionData(1, true, {})
globals.extensionMap["c"] = utils.ExtensionData(1, true, {})
globals.extensionMap["cgi"] = utils.ExtensionData(1, true, {})
globals.extensionMap["charset"] = utils.ExtensionData(1, true, {})
globals.extensionMap["chs"] = utils.ExtensionData(1, true, {})
globals.extensionMap["cht"] = utils.ExtensionData(1, true, {})
globals.extensionMap["cmd"] = utils.ExtensionData(1, true, {})
globals.extensionMap["cpp"] = utils.ExtensionData(1, true, {})
globals.extensionMap["cs"] = utils.ExtensionData(1, true, {})
globals.extensionMap["csh"] = utils.ExtensionData(1, true, {})
globals.extensionMap["css"] = utils.ExtensionData(1, true, {})
globals.extensionMap["csv"] = utils.ExtensionData(1, true, {})
globals.extensionMap["def"] = utils.ExtensionData(1, true, {})
globals.extensionMap["dif"] = utils.ExtensionData(1, true, {})
globals.extensionMap["doc"] = utils.ExtensionData(1, true, {{208,207,17,224,161,177,26,225,},{7,},{37,},{63,215,108,},{10,},})
globals.extensionMap["dtd"] = utils.ExtensionData(1, true, {})
globals.extensionMap["ebd"] = utils.ExtensionData(1, true, {})
globals.extensionMap["fllnks"] = utils.ExtensionData(1, true, {})
globals.extensionMap["git"] = utils.ExtensionData(1, true, {})
globals.extensionMap["gitconfig"] = utils.ExtensionData(1, true, {})
globals.extensionMap["gitignore"] = utils.ExtensionData(1, true, {})
globals.extensionMap["h"] = utils.ExtensionData(1, true, {})
globals.extensionMap["hlp"] = utils.ExtensionData(1, true, {})
globals.extensionMap["htm"] = utils.ExtensionData(1, true, {})
globals.extensionMap["html"] = utils.ExtensionData(1, true, {})
globals.extensionMap["iec"] = utils.ExtensionData(1, true, {})
globals.extensionMap["ime"] = utils.ExtensionData(1, true, {})
globals.extensionMap["inf"] = utils.ExtensionData(1, true, {})
globals.extensionMap["ini"] = utils.ExtensionData(1, true, {})
globals.extensionMap["java"] = utils.ExtensionData(1, true, {})
globals.extensionMap["jnt"] = utils.ExtensionData(1, true, {})
globals.extensionMap["job"] = utils.ExtensionData(1, true, {})
globals.extensionMap["jpn"] = utils.ExtensionData(1, true, {})
globals.extensionMap["js"] = utils.ExtensionData(1, true, {})
globals.extensionMap["json"] = utils.ExtensionData(1, true, {})
globals.extensionMap["jsp"] = utils.ExtensionData(1, true, {})
globals.extensionMap["kor"] = utils.ExtensionData(1, true, {})
globals.extensionMap["lex"] = utils.ExtensionData(1, true, {})
globals.extensionMap["lib"] = utils.ExtensionData(1, true, {})
globals.extensionMap["litesql"] = utils.ExtensionData(1, true, {})
globals.extensionMap["lnk"] = utils.ExtensionData(1, true, {})
globals.extensionMap["log"] = utils.ExtensionData(1, true, {})
globals.extensionMap["log2"] = utils.ExtensionData(1, true, {})
globals.extensionMap["m3u"] = utils.ExtensionData(1, true, {})
globals.extensionMap["man"] = utils.ExtensionData(1, true, {})
globals.extensionMap["manifest"] = utils.ExtensionData(1, true, {})
globals.extensionMap["md"] = utils.ExtensionData(1, true, {})
globals.extensionMap["mht"] = utils.ExtensionData(1, true, {})
globals.extensionMap["mhtml"] = utils.ExtensionData(1, true, {})
globals.extensionMap["mof"] = utils.ExtensionData(1, true, {})
globals.extensionMap["msc"] = utils.ExtensionData(1, true, {})
globals.extensionMap["msg"] = utils.ExtensionData(1, true, {})
globals.extensionMap["nfo"] = utils.ExtensionData(1, true, {})
globals.extensionMap["odb"] = utils.ExtensionData(1, true, {})
globals.extensionMap["odc"] = utils.ExtensionData(1, true, {})
globals.extensionMap["odm"] = utils.ExtensionData(1, true, {})
globals.extensionMap["php"] = utils.ExtensionData(1, true, {})
globals.extensionMap["pl"] = utils.ExtensionData(1, true, {})
globals.extensionMap["pml"] = utils.ExtensionData(1, true, {})
globals.extensionMap["pol"] = utils.ExtensionData(1, true, {})
globals.extensionMap["ppt"] = utils.ExtensionData(1, true, {{208,207,17,224,161,177,26,225,},{7,},{10,},})
globals.extensionMap["prn"] = utils.ExtensionData(1, true, {})
globals.extensionMap["prx"] = utils.ExtensionData(1, true, {})
globals.extensionMap["ps1"] = utils.ExtensionData(1, true, {})
globals.extensionMap["py"] = utils.ExtensionData(1, true, {})
globals.extensionMap["pyc"] = utils.ExtensionData(1, true, {})
globals.extensionMap["qts"] = utils.ExtensionData(1, true, {{77,90,},})
globals.extensionMap["qtx"] = utils.ExtensionData(1, true, {{77,90,},})
globals.extensionMap["rat"] = utils.ExtensionData(1, true, {})
globals.extensionMap["rdp"] = utils.ExtensionData(1, true, {})
globals.extensionMap["rea"] = utils.ExtensionData(1, true, {})
globals.extensionMap["readme"] = utils.ExtensionData(1, true, {})
globals.extensionMap["reg"] = utils.ExtensionData(1, true, {})
globals.extensionMap["resp"] = utils.ExtensionData(1, true, {})
globals.extensionMap["rs"] = utils.ExtensionData(1, true, {})
globals.extensionMap["rss"] = utils.ExtensionData(1, true, {})
globals.extensionMap["rtf"] = utils.ExtensionData(1, true, {{123,92,114,116,102,49,},})
globals.extensionMap["scf"] = utils.ExtensionData(1, true, {})
globals.extensionMap["sdf"] = utils.ExtensionData(1, true, {})
globals.extensionMap["sdi"] = utils.ExtensionData(1, true, {})
globals.extensionMap["sep"] = utils.ExtensionData(1, true, {})
globals.extensionMap["sh"] = utils.ExtensionData(1, true, {})
globals.extensionMap["slk"] = utils.ExtensionData(1, true, {})
globals.extensionMap["sln"] = utils.ExtensionData(1, true, {})
globals.extensionMap["sql"] = utils.ExtensionData(1, true, {})
globals.extensionMap["svg"] = utils.ExtensionData(1, true, {})
globals.extensionMap["text"] = utils.ExtensionData(1, true, {})
globals.extensionMap["tha"] = utils.ExtensionData(1, true, {})
globals.extensionMap["tlb"] = utils.ExtensionData(1, true, {})
globals.extensionMap["tsp"] = utils.ExtensionData(1, true, {})
globals.extensionMap["tt"] = utils.ExtensionData(1, true, {})
globals.extensionMap["txt"] = utils.ExtensionData(1, true, {})
globals.extensionMap["uce"] = utils.ExtensionData(1, true, {})
globals.extensionMap["vb"] = utils.ExtensionData(1, true, {})
globals.extensionMap["vbs"] = utils.ExtensionData(1, true, {})
globals.extensionMap["vbscript"] = utils.ExtensionData(1, true, {})
globals.extensionMap["wmf"] = utils.ExtensionData(1, true, {{215,205,198,154,},})
globals.extensionMap["ws"] = utils.ExtensionData(1, true, {})
globals.extensionMap["wsf"] = utils.ExtensionData(1, true, {})
globals.extensionMap["wsh"] = utils.ExtensionData(1, true, {})
globals.extensionMap["xhtm"] = utils.ExtensionData(1, true, {})
globals.extensionMap["xhtml"] = utils.ExtensionData(1, true, {})
globals.extensionMap["xls"] = utils.ExtensionData(1, true, {{208,207,17,224,161,177,26,225,},{7,},{10,},})
globals.extensionMap["xml"] = utils.ExtensionData(1, true, {})
globals.extensionMap["xsl"] = utils.ExtensionData(1, true, {})
globals.extensionMap["yml"] = utils.ExtensionData(1, true, {})
globals.extensionMap[""] = utils.ExtensionData(1, false, {})
globals.extensionMap["3fr"] = utils.ExtensionData(1, false, {})
globals.extensionMap["arch00"] = utils.ExtensionData(1, false, {})
globals.extensionMap["arw"] = utils.ExtensionData(1, false, {})
globals.extensionMap["asset"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bar"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bay"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bc6"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bc7"] = utils.ExtensionData(1, false, {})
globals.extensionMap["big"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bik"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bkf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bkp"] = utils.ExtensionData(1, false, {})
globals.extensionMap["blob"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bpd"] = utils.ExtensionData(1, false, {})
globals.extensionMap["bsa"] = utils.ExtensionData(1, false, {})
globals.extensionMap["cas"] = utils.ExtensionData(1, false, {})
globals.extensionMap["cdr"] = utils.ExtensionData(1, false, {})
globals.extensionMap["cer"] = utils.ExtensionData(1, false, {})
globals.extensionMap["cfr"] = utils.ExtensionData(1, false, {})
globals.extensionMap["crw"] = utils.ExtensionData(1, false, {})
globals.extensionMap["d3dbsp"] = utils.ExtensionData(1, false, {})
globals.extensionMap["das"] = utils.ExtensionData(1, false, {})
globals.extensionMap["db"] = utils.ExtensionData(1, false, {})
globals.extensionMap["db0"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dba"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dbf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dcr"] = utils.ExtensionData(1, false, {})
globals.extensionMap["der"] = utils.ExtensionData(1, false, {})
globals.extensionMap["desc"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dng"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dwg"] = utils.ExtensionData(1, false, {})
globals.extensionMap["dxg"] = utils.ExtensionData(1, false, {})
globals.extensionMap["eml"] = utils.ExtensionData(1, false, {})
globals.extensionMap["epk"] = utils.ExtensionData(1, false, {})
globals.extensionMap["eps"] = utils.ExtensionData(1, false, {})
globals.extensionMap["erf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["esm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ff"] = utils.ExtensionData(1, false, {})
globals.extensionMap["forge"] = utils.ExtensionData(1, false, {})
globals.extensionMap["fos"] = utils.ExtensionData(1, false, {})
globals.extensionMap["fpk"] = utils.ExtensionData(1, false, {})
globals.extensionMap["fsh"] = utils.ExtensionData(1, false, {})
globals.extensionMap["gdb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["gdl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["gho"] = utils.ExtensionData(1, false, {})
globals.extensionMap["gid"] = utils.ExtensionData(1, false, {})
globals.extensionMap["hdmp"] = utils.ExtensionData(1, false, {})
globals.extensionMap["hkdb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["hkx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["hplg"] = utils.ExtensionData(1, false, {})
globals.extensionMap["hvpl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ibank"] = utils.ExtensionData(1, false, {})
globals.extensionMap["icxs"] = utils.ExtensionData(1, false, {})
globals.extensionMap["indd"] = utils.ExtensionData(1, false, {})
globals.extensionMap["itdb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["itl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["itm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["iwd"] = utils.ExtensionData(1, false, {})
globals.extensionMap["iwi"] = utils.ExtensionData(1, false, {})
globals.extensionMap["kdb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["kdc"] = utils.ExtensionData(1, false, {})
globals.extensionMap["kf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["layout"] = utils.ExtensionData(1, false, {})
globals.extensionMap["lbf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["litemod"] = utils.ExtensionData(1, false, {})
globals.extensionMap["lock"] = utils.ExtensionData(1, false, {})
globals.extensionMap["lrf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ltx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["lvl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["m2"] = utils.ExtensionData(1, false, {})
globals.extensionMap["map"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mcmeta"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mdb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mdbackup"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mddata"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mdf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mef"] = utils.ExtensionData(1, false, {})
globals.extensionMap["menu"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mk3d"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mlx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mpqge"] = utils.ExtensionData(1, false, {})
globals.extensionMap["mrwref"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ncf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["nrw"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ntf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ntl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["orf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["p12"] = utils.ExtensionData(1, false, {})
globals.extensionMap["p7b"] = utils.ExtensionData(1, false, {})
globals.extensionMap["p7c"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pak"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pdd"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pef"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pem"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pfx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pif"] = utils.ExtensionData(1, false, {})
globals.extensionMap["pma"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ppd"] = utils.ExtensionData(1, false, {})
globals.extensionMap["psk"] = utils.ExtensionData(1, false, {})
globals.extensionMap["ptx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["qdf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["qic"] = utils.ExtensionData(1, false, {})
globals.extensionMap["r3d"] = utils.ExtensionData(1, false, {})
globals.extensionMap["raf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["raw"] = utils.ExtensionData(1, false, {})
globals.extensionMap["rb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["re4"] = utils.ExtensionData(1, false, {})
globals.extensionMap["rgss3a"] = utils.ExtensionData(1, false, {})
globals.extensionMap["rim"] = utils.ExtensionData(1, false, {})
globals.extensionMap["rofl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["rw2"] = utils.ExtensionData(1, false, {})
globals.extensionMap["rwl"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sav"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sid"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sidd"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sidn"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sie"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sis"] = utils.ExtensionData(1, false, {})
globals.extensionMap["size"] = utils.ExtensionData(1, false, {})
globals.extensionMap["slm"] = utils.ExtensionData(1, false, {})
globals.extensionMap["snx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sr2"] = utils.ExtensionData(1, false, {})
globals.extensionMap["srf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["srw"] = utils.ExtensionData(1, false, {})
globals.extensionMap["sum"] = utils.ExtensionData(1, false, {})
globals.extensionMap["syncdb"] = utils.ExtensionData(1, false, {})
globals.extensionMap["t12"] = utils.ExtensionData(1, false, {})
globals.extensionMap["t13"] = utils.ExtensionData(1, false, {})
globals.extensionMap["tax"] = utils.ExtensionData(1, false, {})
globals.extensionMap["tmp"] = utils.ExtensionData(1, false, {})
globals.extensionMap["tor"] = utils.ExtensionData(1, false, {})
globals.extensionMap["upk"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vcf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vdf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vpk"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vpp_pc"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vsdx"] = utils.ExtensionData(1, false, {})
globals.extensionMap["vtf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["w3x"] = utils.ExtensionData(1, false, {})
globals.extensionMap["wb2"] = utils.ExtensionData(1, false, {})
globals.extensionMap["wpd"] = utils.ExtensionData(1, false, {})
globals.extensionMap["wps"] = utils.ExtensionData(1, false, {})
globals.extensionMap["x3f"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xf"] = utils.ExtensionData(1, false, {})
globals.extensionMap["xlk"] = utils.ExtensionData(1, false, {})

----

globals.EXTENSION_IGNORED = 0
globals.EXTENSION_MONITORED = 1
globals.EXTENSION_SUSPICIOUS = 2
globals.EXTENSION_UNKNOWN = 3

globals.unknownExtensionData = utils.ExtensionData(globals.EXTENSION_UNKNOWN, false, {})

-- start ransomware extensions
globals.extensionMap['0x0'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['1999'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['73i87a'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['777'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['7h9r'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['8lock8'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['____xratteamlucked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['___xratteamlucked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['_airacropencrypted'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['_crypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['_nullbyte'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['_ryp'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['acuna'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['adam'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['adolfhitler'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['aes256'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['aga'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['alcatraz'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['amba'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['angelamerkel'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['angleware'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['antihacker2017'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['arena'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['babyk'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bagli'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['barrax'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bart'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['better_call_saul'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bitpy'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bitstak'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['blackruby'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bleepyourfiles'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bloc'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['blocatto'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['braincrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['breaking_bad'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bript'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['btc'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['btc - help - you'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['btcbtcbtc'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['btcware'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['bullet'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cccrrrppp'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cerber'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cerber2'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cerber3'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cesar'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['chernolocker)'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['chifrator@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['chip'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ciop'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['clop'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['coded'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['com]'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['com___'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['comrade'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['coverton'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crab'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crashed'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crime'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crinf'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['criptiko'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['criptoko'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['criptokod'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cripttt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crjoker'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crptrgr'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crrrt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cry_'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cryp1'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crypt38'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crypted'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crypted_file'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crypto'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cryptoshiel'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cryptoshield'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cryptotorlocker2015!'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cryptz'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crypz'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['crysis'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['cuba'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['czvxce'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['d4nk'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['da_vinci_code'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['dale'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['damage'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['darkness'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['dcrtr'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['dcry'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['dcrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ddsg'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['deep'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['deria'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['deuscrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['dharma'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['disappeared'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['donut'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['doomed'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['dxxd'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['dyatel@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['edgel'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ehiz'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['embrace'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['encedrsa'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['enciphered'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['encoderpass'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['encr'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['encryptedaes'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['encryptedrsa'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['enigma'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['es_helps'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['evil'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['evillock'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['exotic'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ezz'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['fantom'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['fear'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['file0locked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['fileiscryptedhard'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['filock'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['firecrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['frtrss'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['fs0ciety'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['fuck'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['fucked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['fuckyourdata'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['gdcb'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['gruzin@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['gujd'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['h3ll'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ha3'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['hannah'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['hanta'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['happy new year'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['hb15'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['helpdecrypt@ukr.net'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['herbst'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['hive'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['honor'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['id-_locked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['id-_locked_by_krec'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['id-_locked_by_perfect'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['id-_r9oj'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['id-_x3m'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['igvm'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['iiohy'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['infected'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['insane'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['iqll'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['jest'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['jey'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['josep'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['justbtcwillhelpyou'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['karma'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kencf'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['keybtc@inbox_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['keyh0les'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['keyz'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['killedxxx'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kimcilware'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['king_ouroboros'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kirked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kkk'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['korrektor'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kostya'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kr3'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['krab'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kraken'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['kratos'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['l0cked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['lechiffre'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['leex'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['legion'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['leon'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['lesli'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['licked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['lock93'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['lockbit'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['locked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['locked-[xxx]'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['locked_file'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['locklock'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['locky'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['lol!'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['lovewindows'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['lssr'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['madebyadam'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['megac0rtx'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['miis'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['mpqq'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['nalog@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['neer'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['nefilim'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['no_more_ransom'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['nochance'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['nuclear55'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['nusm'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['nwji'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['odcodc'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ohno!'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['omg!'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['oops'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['oor'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['oplata@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['oshit'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['p5tkjw'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['paas'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['padcrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['pahad'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['pahd'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['pain'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['payrmts'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['pcqq'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['piiq'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['pizda@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['poar2w'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['pooe'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['porno'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['potato'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['prolock'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['pysa'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['qscx'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['qwerty'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['r4a'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['r5a'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['radamant'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ragnarok'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['ransomaes'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['razy'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rdmk'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rejg'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rekt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['relock@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['remind'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['revenge'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rnsmwr'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rokku'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rrk'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rsnslocked'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['rsplited'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sage'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sanction'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['satyr'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['securecrypted'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sepsis'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['serpent'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sexy'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['shinigami'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['shino'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sick'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sifreli'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sigrun'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['silent'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sport'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['sspq'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['surprise'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['thetrumplockerf'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['thetrumplockerp'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['toxcrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['triple_m'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['tron'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['troyancoder@qq_com'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['trun'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['tzu'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['unavailable'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['vault'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['vbransom'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['velikasrbija'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['venusf'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['venusp'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['versiegelt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['vindows'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['volcano'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['vscrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['vxlock'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['wcry'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['wflx'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['whiterose'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['windows10'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['wnx'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['wwka'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['wyvern'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['x3m'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['xcri'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['xmdxtazx'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['xort'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['xrtn'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['xtbl'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['yourransom'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['z81928819'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['zcrypt'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['zino'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['zorro'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['zqqw'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['zyklon'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['zzla'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})
globals.extensionMap['{crypttendblackdc)'] = utils.ExtensionData(globals.EXTENSION_SUSPICIOUS, false, {})

-- Canary represents a canary file object.
-- @param fullpath string: canary full destination path (required)
-- @param content string: content of the canary file (required).
-- @param hidden bool: true sets the file attributes to hidden.
-- @param force bool: true forces the creation of the file.
-- @param system bool: true sets the file attributes to system .
-- @return table representing the the canary file or nil.
function globals.Canary(fullpath, content, force, hidden, system)

    -- sanity check for required fields.
    if fullpath == nil or content == nil then
        return nil
    end

    -- by default, force create files.
    if force == nil then
        force = true
    end

    -- by default, do not hide files.
    if hidden == nil then
        hidden = false
    end

    -- by default, create a regular file.
    if system == nil then
        system = false
    end

    local namesList = utils.Split(fullpath, '\\')
    if #namesList <= 2 then
        return nil
    end

    local filename = namesList[#namesList]:lower()
    local dirname = namesList[#namesList - 1]:lower()

    local self = {}
    self.force = force
    self.hidden = hidden
    self.system = system
    self.fullpath = fullpath
    self.filename = filename
    self.dirname = dirname
    self.content = content
    return self
end

-- Create a canary file content. This function should be improved later to take
-- a mime type and generate a valid canary file type.
function globals.CreateCanaryContent()

    local header = 'This is a canary file to detect ransomware. Please do not'
    header = header .. ' modify or delete it.\n\n\n'

    -- math.randomseed(os.time())
    -- local r = math.random(1, 20)
    local lorem = [[ Lorem ipsum dolor sit amet, consectetur adipiscing elit,
    sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.Ut enim
    ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip
    ex ea commodo consequat.Duis aute irure dolor in reprehenderit in voluptate
    velit esse cillum dolore eu fugiat nulla pariatur.Excepteur sint occaecat
    cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    ]]

    local canaryContent = header
    for _ = 1, 20 do
        canaryContent = canaryContent .. lorem
    end

    return canaryContent
end

-- This function checks for file creation events in any canary directory OR
-- any file events (except DELETE and OPEN) related to canary files.
function globals.Lua_CanaryCheck(eventData)
    local subDir = nil
    local filePath = eventData.filePath:lower()
    for _, dirName in ipairs(globals.namespace.canaryDirNames) do
        subDir = string.find(filePath, dirName, nil, true)
        if nil ~= subDir then
            -- event involves a canary directory
            break
        end
    end

    if nil == subDir then
        return false
    end

    local fileName = eventData.fileName:lower()
    for _, canaryFileName in ipairs(globals.namespace.canaryFileNames) do
        local subFile = string.find(fileName, canaryFileName, nil, true)
        if globals.FILE_CREATE_NEW == eventData.operation then
            utils.DebugLog('NEW FILE IN CANARY DIRECTORY!!!!!')
            if globals.namespace.totalCanaryCreateFileAlerts >= globals.CANARY_CREATE_FILE_ALERT_CAP then
                utils.DebugLog('CANARY CREATE FILE THRESHOLD REACHED')
            else
                globals.namespace.totalCanaryCreateFileAlerts = globals.namespace.totalCanaryCreateFileAlerts + 1
                return true
            end
        elseif (nil ~= subFile) and (globals.FILE_DELETE ~= eventData.operation) and
            (globals.FILE_OPEN ~= eventData.operation) then
            utils.DebugLog('CANARY FILE EVENT!!!!!!')
            return true
        end
    end

    return false
end

-- set a custom config metrics
function globals.SetConfig(newConfig)
    globals.config = newConfig
end

-- set a custom extension map
function globals.SetExtensionMap(newExtensionMap)
    globals.extensionMap = newExtensionMap
end

-- set custom ignore paths
function globals.SetIgnorePaths(newIgnorePaths)
    globals.regexIgnorePaths = newIgnorePaths
end

--------------------------------------------------------------
-- GLOBAL FUNCTIONS
-- Common functions that will be called by separate namespaces
--------------------------------------------------------------

-- Used to track the namespace currently being used so any associated debug
-- logging can be tagged with the appropriate namespace. In the future,
-- we could write namespace-specific logic in shared global functions to reduce
-- code duplication.
function globals.SwitchNamespace(newNamespace)
    globals.namespace = newNamespace
end

-- In order to work around 3.53 limitation that limits processes to one alert,
-- we will queue diagnostic alerts (in order to give standard alerts priority)
-- until the process:
-- 1) Generates a standard alert.
-- 2) Meets the file event threshold.
-- 3) Is terminated.
-- Once one of these conditions is met, we consult the relevant ProcessData
-- object in the diagnostic namespace to determine if a diagnostic alert was
-- previously queued; if one has, then we invoke the GenerateAlert function.
-- @param processId integer: The subject process identifier.
function globals.CheckForQueuedDiagnosticAlert(processId)
    local currentNamespace = globals.namespace

    if (#globals.namespaces == 1) and (currentNamespace.isDiagnostic == false) then
        return false
    end

    for _, namespace in pairs(globals.namespaces) do
        if namespace.isDiagnostic then
            globals.SwitchNamespace(namespace)
            break
        end
    end

    if utils.TableHasKey(globals.namespace.processDataTable, processId) then
        local diagnosticProcessData = globals.namespace.processDataTable[processId]

        if diagnosticProcessData.diagnosticAlertQueued then
            utils.DebugLog('diagnosticAlertQueued: ' .. processId)
            alert.GenerateAlert(diagnosticProcessData, true)
        end
    end

    globals.SwitchNamespace(currentNamespace)
end

-- Sanitizes the paths, names, and extensions for the provided event.
-- @param eventData table: A table containing event data.
-- @return void.
function globals.CleanEventData(eventData)
    if utils.TableHasKey(eventData, 'filePath') then
        eventData.filePath = utils.RemoveAdsFromPath(eventData.filePath)
        eventData.fileName = eventData.filePath:match('[^\\]+$')
    end

    if utils.TableHasKey(eventData, 'fileExtension') then
        eventData.fileExtension = utils.RemoveAdsFromPath(eventData.fileExtension)
    end

    if utils.TableHasKey(eventData, 'filePreviousPath') then
        eventData.filePreviousPath = utils.RemoveAdsFromPath(eventData.filePreviousPath)
        eventData.filePreviousName = eventData.filePreviousPath:match('[^\\]+$')
    end

    if utils.TableHasKey(eventData, 'filePreviousExtension') then
        eventData.filePreviousExtension = utils.RemoveAdsFromPath(eventData.filePreviousExtension)
    end

    if utils.IsOfficeLockFile(eventData.fileExtension, eventData.fileName) then
        utils.DebugLog('OFFICE LOCK FILE: ' .. eventData.filePath)
        eventData.officeLockFile = true
    else
        eventData.officeLockFile = false
    end
end

-- Updates the extension table. This function inserts the extension name to the
-- appropriate process data extension table according to the file operation.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return void.
function globals.UpdateExtensionTables(eventData, processData)
    if globals.FILE_CREATE_NEW == eventData.operation then
        if not utils.TableHasKey(processData.createExtensions, eventData.fileExtension) then
            processData.createExtensions[eventData.fileExtension] = {}
        end
        table.insert(processData.createExtensions[eventData.fileExtension], eventData)
    elseif globals.FILE_MODIFY == eventData.operation then
        if not utils.TableHasKey(processData.modifyExtensions, eventData.fileExtension) then
            processData.modifyExtensions[eventData.fileExtension] = {}
        end
        table.insert(processData.modifyExtensions[eventData.fileExtension], eventData)
    elseif globals.FILE_DELETE == eventData.operation then
        if not utils.TableHasKey(processData.deleteExtensions, eventData.fileExtension) then
            processData.deleteExtensions[eventData.fileExtension] = {}
        end
        table.insert(processData.deleteExtensions[eventData.fileExtension], eventData)
    elseif globals.FILE_RENAME == eventData.operation then
        if not utils.TableHasKey(processData.renameExtensions, eventData.fileExtension) then
            processData.renameExtensions[eventData.fileExtension] = {}
        end
        table.insert(processData.renameExtensions[eventData.fileExtension], eventData)

        if not utils.TableHasKey(processData.renamePreviousExtensions, eventData.filePreviousExtension) then
            processData.renamePreviousExtensions[eventData.filePreviousExtension] = {}
        end
        table.insert(processData.renamePreviousExtensions[eventData.filePreviousExtension], eventData)

    elseif globals.FILE_OVERWRITE == eventData.operation then
        if not utils.TableHasKey(processData.overwriteExtensions, eventData.fileExtension) then
            processData.overwriteExtensions[eventData.fileExtension] = {}
        end
        table.insert(processData.overwriteExtensions[eventData.fileExtension], eventData)
    end
end

-- Build the list of canary files to be planted.
function globals.BuildCanaries()

    local canaries = {}
    local canaryDirNames = {}
    local canaryFileNames = {}
    local canaryExtensions = {'txt', 'doc', 'docx', 'docm', 'dot', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm'}

    -- Generate a canary file content, for now all canary files have the same content.
    local canaryContent = globals.CreateCanaryContent()

    -- Get the %windir%.
    local windowsPath = GetKnownFolderPath('{F38BF404-1D43-42F2-9305-67DE0B28FC23}')

    if globals.namespace.diagnosticMode then
        canaryDirNames = {
            'aaAntiRansomElastic-DO-NOT-TOUCH-def6d40c-a6a1-442c-adc4-9d57a47e58d7',
            'zzAntiRansomElastic-DO-NOT-TOUCH-def6d40c-a6a1-442c-adc4-9d57a47e58d7'
        }
        canaryFileNames = {'AntiRansomElastic-DO-NOT-TOUCH-def8452b-fc17-414d-afb6-ddeceb5ec54c'}
    else
        canaryDirNames = {
            'aaAntiRansomElastic-DO-NOT-TOUCH-dab6d40c-a6a1-442c-adc4-9d57a47e58d7',
            'zzAntiRansomElastic-DO-NOT-TOUCH-dab6d40c-a6a1-442c-adc4-9d57a47e58d7'
        }
        canaryFileNames = {'AntiRansomElastic-DO-NOT-TOUCH-4568452b-fc17-414d-afb6-ddeceb5ec54c'}
    end

    for _, dirName in ipairs(canaryDirNames) do
        for _, fileName in ipairs(canaryFileNames) do
            for _, ext in ipairs(canaryExtensions) do
                local canaryFileName = fileName .. '.' .. ext

                -- Iterate over all user directories.
                for _, userProfile in ipairs(utils.GetAllUserProfiles()) do
                    local canaryFullPath = userProfile .. '\\' .. dirName .. '\\' .. canaryFileName
                    local canary = globals.Canary(canaryFullPath, canaryContent)
                    table.insert(canaries, canary)
                end

                -- Include also the root directory.
                local canaryFullPath = windowsPath .. '\\..\\' .. dirName .. '\\' .. canaryFileName
                local canary = globals.Canary(canaryFullPath, canaryContent)
                table.insert(canaries, canary)
            end
        end
    end

    return canaries
end

------------------------------------------------------------------------
-- SENSOR FUNCTIONS
-- These functions are not grouped under a table so they can be called
-- directly by the sensor
------------------------------------------------------------------------

-- Garbage collection routine which manually nils out ProcessData objects that
-- appear to be expired and then invokes the lua garbage collection.
function GarbageCollect()
    utils.DebugLog('*** GarbageCollect INVOKED')
    utils.DebugLog('[lua] Current Memory Usage: ' .. collectgarbage('count'))

    local totalPidsToNil = 0

    for _, v1 in pairs(globals.namespaces) do
        globals.SwitchNamespace(v1)
        local pidsToNil = {}

        for k2, v2 in pairs(globals.namespace.processDataTable) do
            utils.DebugLog('[lua] PID: ' .. k2)
            utils.DebugLog('[lua] totalScore: ' .. v2.totalScore)
            utils.DebugLog('[lua] Number events: ' .. #v2.events)

            if #v2.events >= globals.PROCESS_EVENT_THRESHOLD then
                utils.DebugLog('[lua] Blow away this PID: ' .. k2)
                table.insert(pidsToNil, k2)
                totalPidsToNil = totalPidsToNil + 1
            end
        end

        for _, v2 in pairs(pidsToNil) do
            globals.namespace.processDataTable[v2] = nil
        end
    end

    if totalPidsToNil > 0 then
        collectgarbage()
        utils.DebugLog('[lua] Cleaned Up Memory Usage: ' .. collectgarbage('count'))
    end

    return true
end

-- Sends global variable data to the sensor via `lemit`.
function GetGlobals()
    local globalsTable = {}
    globalsTable.clear_config = true
    globalsTable.threshold = globals.PROCESS_EVENT_THRESHOLD * 1.0
    globalsTable.regexes = globals.regexIgnorePaths

    local ignoreExtensions = {}

    for k, v in pairs(globals.extensionMap) do
        if globals.EXTENSION_IGNORED == v.category then
            utils.DebugLog('IGNORED: ' .. k)
            table.insert(ignoreExtensions, k)
        end
    end

    globalsTable.strings = ignoreExtensions
    lemit(globalsTable)
    return true
end

-- Removes ProcesData object for the given PID from the relevant namespace(s).
-- @param processId integer: The subject process identifier.
function RemoveProcessData(processId)
    utils.DebugLog('*** RemoveProcessData INVOKED')
    utils.DebugLog('[lua] Removing processId: ' .. processId)

    ------------------------------------------
    globals.CheckForQueuedDiagnosticAlert(processId)
    ------------------------------------------

    for _, v in pairs(globals.namespaces) do
        globals.SwitchNamespace(v)

        if utils.TableHasKey(globals.namespace.processDataTable, processId) then
            globals.namespace.processDataTable[processId] = nil
            utils.DebugLog('[lua] processDataTable entry removed: ' .. processId)
        else
            utils.DebugLog('[lua] Could not find entry in processDataTable: ' .. processId)
        end
    end

    return true
end

-- uses lemit to send a table to the sensor summarizing all event activity observed;
-- intended for use with the LuaRansomware tool to indicate if an alert was generated
function EventsSummary()
    local tempTable = {}
    local summary = ''
    local totalPids = 0
    local totalEvents = 0
    local totalScore = 0.0

    local numRenameExtensions = 0
    local operations = ''

    for _, v1 in pairs(globals.namespaces) do
        totalPids = 0
        totalEvents = 0
        totalScore = 0.0

        for k2, v2 in pairs(v1.processDataTable) do
            if utils.TableHasKey(v2, 'parentProcessId') then
                summary = summary .. '\nPID: ' .. k2 .. ' | PPID: ' .. v2.parentProcessId .. ' | numEvents: ' ..
                              #v2.events .. ' | totalScore:' .. v2.totalScore
            else
                summary = summary .. '\nPID: ' .. k2 .. ' | numEvents: ' .. #v2.events .. ' | totalScore:' ..
                              v2.totalScore
            end

            if utils.TableHasKey(v2, 'children') then
                for k3, v3 in pairs(v2.children) do
                    summary = summary .. '\nCHILD PID: ' .. k2 .. ' | SCORE: ' .. v2
                end
            end

            totalPids = totalPids + 1
            totalEvents = totalEvents + #v2.events
            totalScore = totalScore + v2.totalScore

            local renames = 0

            for _, v in pairs(v2.renameExtensions) do
                renames = 1
                break
            end

            if 1.0 < v2.totalScore then
                operations = operations .. '\n' .. utils.PrintOperationTables(v2)
            end
        end

        if 0 < totalPids then
            summary = summary .. '\nPIDS: ' .. totalPids .. ' EVENTS: ' .. totalEvents .. ' TOTAL TRACE SCORE: ' ..
                          totalScore
            summary = summary .. operations
        end
    end

    summary = summary .. '\n<END>'

    tempTable.raw_data = summary
    tempTable.is_alert = globals.alertGenerated
    lemit(tempTable)
    return true
end

-- Explicitly enable debug logging.
function EnableLogging()
    llog('ENABLED')
    globals.logging = true
    return true
end

-- This function is called by the ransomware plugin during startup to create
-- canary files.
function CanaryStartup()

    utils.DebugLog('Canary Startup Called')

    local product = utils.GetProduct()
    if product ~= 'elastic' then
        utils.DebugLog('Not initiating canary startup (non-elastic endpoint)')
        return
    end

    -- Check compatibility (Elastic 8.6.0+)
    local incompatible = utils.CurrentVersionLessThan('8.6.0')
    if incompatible then
        utils.DebugLog('Not initiating canary startup (version < 8.6.0)')
        return
    end

    utils.DebugLog('Elastic endpoint version is compatible with canary files!')
    globals.canaryCompatible = true

    -- Clean up any leftovers from previous runs.
    CanariesCleanup(globals.namespace.diagnosticMode)

    -- If we're not dropping canaries, just exit.
    if (false == CanariesEnabled()) then
        return
    end

    -- iterate over each namespace.
    for _, namespace in pairs(globals.namespaces) do
        globals.SwitchNamespace(namespace)

        utils.DebugLog('build the list of canary files to be created')
        local canaries = globals.BuildCanaries()
        if next(canaries) == nil then
            utils.DebugLog('failed to build the list of canary files')
            return
        end

        -- iterate over the list of canary files and plant them.
        local canaryPlanted = false
        utils.DebugLog('planting canary files')
        for _, canary in ipairs(canaries) do

            -- PlantCanary invokes the endpoint to plant a canary file in a staging directory,
            -- (C:\Program Files\Elastic\Endpoint\temp\<staging_dir>). The lua code is explicitly
            -- not involving the choice of this staging directory because it is not interesting
            -- for the lua side and can be subject to change in the future.
            -- Once all canaries have been planted, a call to`CommitCanaries()` is required to make
            -- an atomic move from those staging directories to the appropriate target directories.
            local canaryStatus =
                PlantCanary(canary.fullpath, canary.content, canary.hidden, canary.force, canary.system)
            if canaryStatus == nil then
                utils.DebugLog('failed to plant canary: ' .. canary.fullpath)
            else
                -- Keep track of the canary directory names and canary file names,
                -- so we can easily make comparisons later in the CanaryCheck.
                if not utils.TableHasValue(globals.namespace.canaryDirNames, canary.dirname) then
                    table.insert(globals.namespace.canaryDirNames, canary.dirname)
                end
                if not utils.TableHasValue(globals.namespace.canaryFileNames, canary.filename) then
                    table.insert(globals.namespace.canaryFileNames, canary.filename)
                end
                canaryPlanted = true
            end
        end

        -- If no canary files were planted, abort.
        if canaryPlanted == false then
            utils.DebugLog('Failed to drop any canaries!')
            return
        end

        -- all good, keep track that we have successfully droped canaries.
        if globals.namespace.diagnosticMode then
            globals.diagnosticCanariesDropped = true
        else
            globals.productionCanariesDropped = true
        end
    end

    return true
end

-- main function invoked by the endpoint/sensor to process individual file events.
-- @data table: A table representing the raw file event.
function main(data)

    for _, namespace in pairs(globals.namespaces) do
        globals.SwitchNamespace(namespace)
        globals.CleanEventData(data)
        namespace:Main(data)
    end

    return true
end


local Ransomware = {}

function Ransomware:new(o)
    o = o or {}
    o.totalAlerts = 0
    o.canaryDirNames = {}
    o.canaryFileNames = {}
    o.processDataTable = {}
    o.totalCanaryCreateFileAlerts = 0
    setmetatable(o, self)
    self.__index = self
    return o
end

-- Creates a process data object. This table tracks numerous properties of the
-- process such as its ransomware score, its parent and its children.
-- @param processId int: Process identifier.
-- @param parentProcessId int: Parent process identifier.
-- @return table: A table representing the process data.
function Ransomware.ProcessData(processId, parentProcessId)
    local obj = {}
    obj.events = {}
    obj.headerMismatchExtensions = {}
    obj.numHeaderMismatchExtensions = 0
    obj.entropyMismatchExtensions = {}
    obj.numEntropyMismatchExtensions = 0

    obj.createExtensions = {}
    obj.modifyExtensions = {}
    obj.deleteExtensions = {}
    obj.renameExtensions = {}
    obj.renamePreviousExtensions = {}
    obj.overwriteExtensions = {}

    obj.subExtensions = {}
    obj.longExtensions = {}
    obj.appendedPaths = {}

    -- Represents a table of unique directories in terms of responsibility
    -- that the process has touched.
    obj.uniqueDirectoriesByResponsibility = {}
    obj.createFileNames = {}

    obj.totalEventScore = 0.0
    obj.trendScore = 0.0
    obj.totalScore = 0.0
    obj.processId = processId
    obj.parentProcessId = parentProcessId
    obj.children = {}
    obj.childScore = 0.0
    obj.diagnosticAlerted = false
    obj.diagnosticAlertQueued = false
    obj.alerted = false
    obj.activeAnalysis = true
    obj.eventThresholdExtended = false
    return obj
end

-- Creates an event data object. This table contains attributes related the current
-- event such as its file path, filename, entropy, extension.
-- @param inputData table: Process identifier.
-- @return table: A table representing the event data.
function Ransomware:EventData(inputData)
    local obj = {}

    obj.processId = inputData.processId
    obj.operation = inputData.fileOperation
    obj.fileExtension = inputData.fileExtension
    obj.entropy = inputData.entropy
    obj.filePath = inputData.filePath
    obj.fileName = obj.filePath:match('[^\\]+$')

    -- alternate data streams were leading to inaccurate process scores; ideally these would
    -- be removed on the sensor but this will be handled in lua for the time being
    obj.filePath = utils.RemoveAdsFromPath(obj.filePath)
    obj.fileName = utils.RemoveAdsFromExtension(obj.fileName)
    obj.fileExtension = utils.RemoveAdsFromExtension(obj.fileExtension)

    obj.headerString = ''
    obj.headerBytes = {}

    obj.officeLockFile = inputData.officeLockFile

    obj.parentProcessId = globals.INVALID_PROCESS_ID

    if utils.TableHasKey(inputData, 'parentProcessId') then
        obj.parentProcessId = inputData.parentProcessId
    end

    obj.renameTransition = globals.DEFAULT_RENAME
    obj.alertScore = 0.0
    obj.multipleExtension = false
    obj.alertMetrics = {}

    obj.headerMismatch = false
    obj.previousHeaderMismatch = false
    obj.entropyStatus = globals.ENTROPY_STATUS_DEFAULT
    obj.previousEntropyStatus = globals.ENTROPY_STATUS_DEFAULT
    obj.numAbnormalExtensionCharacters = 0

    if globals.FILE_RENAME == obj.operation then
        obj.filePreviousPath = inputData.filePreviousPath
        obj.filePreviousExtension = inputData.filePreviousExtension
        obj.filePreviousName = obj.filePreviousPath:match('[^\\]+$')
    end

    if utils.TableHasKey(inputData, 'headerString') then
        obj.headerString = inputData.headerString
    elseif utils.TableHasKey(inputData, 'headerBytes') then
        obj.headerString = inputData.headerBytes
    end

    obj.headerBytes = utils.StringToByteArray(obj.headerString)
    obj.headerString = utils.Hexlify(obj.headerString)

    obj.currentExtensionData = nil
    obj.previousExtensionData = nil

    obj.normalizedPath = utils.NormalizePath(obj.filePath)

    self.SetExtensionData(obj)

    return obj
end

-- Create an extension object for the given event data. In case of a rename
-- operation, an additional `previous` extension object is created.
-- @param eventData table: A table containing event data.
-- @return void.
function Ransomware.SetExtensionData(eventData)
    if utils.TableHasKey(globals.extensionMap, eventData.fileExtension) then
        eventData.currentExtensionData = globals.extensionMap[eventData.fileExtension]
    else
        eventData.currentExtensionData = globals.unknownExtensionData
    end

    if globals.FILE_RENAME == eventData.operation then
        if eventData.filePreviousExtension ~= eventData.fileExtension then
            if utils.TableHasKey(globals.extensionMap, eventData.filePreviousExtension) then
                eventData.previousExtensionData = globals.extensionMap[eventData.filePreviousExtension]
            else
                eventData.previousExtensionData = globals.unknownExtensionData
            end
        else
            eventData.previousExtensionData = eventData.currentExtensionData
        end
    end
end

-- Turns off active analysis for a specified process.
-- @param processData table: A table containing process data.
-- @return void.
function Ransomware.StopActiveAnalysis(processData)
    processData.activeAnalysis = false
end

-- Sends a message to the endpoint informing it to stop monitoring a specified
-- process.
-- @param processData table: A table containing process data.
-- @return table: Table representing the process table.
function Ransomware:SendStopActiveAnalysisMsg(processData)
    utils.PrintExtensionTables(processData)
    utils.PrintOperationTables(processData)
    self.StopActiveAnalysis(processData)

    local processTable = {}
    processTable.pid = processData.processId
    processTable.is_alert = false

    -- The sensor/endpoint still both use the 'beta_alert' key
    processTable.beta_alert = self.diagnosticMode
    processTable.score = processData.totalScore
    lemit(processTable)
    return processTable
end

-- Skips duplicate file events.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return boolean: True when the event is a duplicate, False otherwise.
function Ransomware.DuplicateEventCheck(eventData, processData)
    for _, v in pairs(processData.events) do
        if v.filePath == eventData.filePath then
            if v.operation == eventData.operation then
                if globals.FILE_RENAME ~= v.operation then
                    utils.DebugLog('SKIPPING DUPLICATE EVENT: ' .. eventData.filePath)
                    return true
                elseif v.filePreviousPath == eventData.filePreviousPath then
                    utils.DebugLog('SKIPPING DUPLICATE RENAME: ' .. eventData.filePath)
                    return true
                else
                    utils.DebugLog('VALID rename: ' .. eventData.filePath)
                    return false
                end
            end
        end
    end

    return false
end

-- PathHistory evaluates the current event and how it relates to previous events
-- involving the same filepath within the same process. In particular, we seek to
-- find anomalous file modification patterns that may not be apparent when analyzing
-- the current event in a vacuum (e.g. deleting and creating the same filepath).
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return void.
function Ransomware.PathHistory(eventData, processData)
    local pathEvents = {}
    local previousPathEvents = {}
    local pathEventTable = {}

    for _, v in pairs(processData.events) do
        if not utils.TableHasKey(pathEventTable, v.filePath) then
            pathEventTable[v.filePath] = {}
        end

        table.insert(pathEventTable[v.filePath], v.operation)
    end

    for _, v in pairs(processData.events) do
        if v.filePath == eventData.filePath then
            if v.operation == eventData.operation then
                utils.DebugLog('SKIPPING DUPLICATE EVENT (DuplicateEventCheck fail): ' .. eventData.filePath)
                return true
            end

            table.insert(pathEvents, v)

        elseif globals.FILE_RENAME == eventData.operation then
            if v.filePath == eventData.filePreviousPath then
                utils.DebugLog('added to previousPathEvents: ' .. v.filePath)
                table.insert(previousPathEvents, v)
            end

        elseif globals.FILE_DELETE == eventData.operation then
            local subString = string.find(v.filePath, eventData.filePath, nil, true)
            if nil ~= subString then
                utils.DebugLog('deleted filePath found as substring in different event with different filePath')

                -- Was this filepath previously created or renamed? if so, BREAK
                local prevCreate = false
                local prevRename = false

                if nil ~= pathEventTable[eventData.filePath] then
                    for _, prevOperation in pairs(pathEventTable[eventData.filePath]) do
                        if globals.FILE_CREATE_NEW == prevOperation then
                            utils.DebugLog('globals.FILE_CREATE_NEW == prevOperation')
                            prevCreate = true
                            break
                        elseif globals.FILE_RENAME == prevOperation then
                            utils.DebugLog('globals.FILE_RENAME == prevOperation')
                            prevRename = true
                            break
                        end
                    end
                end

                if prevCreate then
                    utils.DebugLog('prevCreate detected for eventData.filePath')
                    break
                elseif prevRename then
                    utils.DebugLog('prevRename detected for eventData.filePath')
                    break
                end

                alert.RaiseFileAlertMetric(eventData, 'DELETED_PATH_SUBSTRING_FOUND')

                if globals.FILE_CREATE_NEW == v.operation then
                    utils.DebugLog('substring was previously created...')
                    local prevDelete = false

                    for _, prevOperation in pairs(pathEventTable[v.filePath]) do
                        if globals.FILE_DELETE == prevOperation then
                            utils.DebugLog('globals.FILE_DELETE == prevOperation')
                            prevDelete = true
                            break
                        end
                    end

                    if prevDelete then
                        utils.DebugLog('prevDelete detected for v.filePath!!!')
                        break
                    end

                    if globals.EXTENSION_SUSPICIOUS == v.currentExtensionData.category then
                        utils.DebugLog('ALERT_SCORE_CHANGE: DELETE_EXTENSION_BLOCKLIST_PREVIOUSLY_CREATED_FILEPATH: ' ..
                                           globals.config.DELETE_EXTENSION_BLOCKLIST_PREVIOUSLY_CREATED_FILEPATH['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config.DELETE_EXTENSION_BLOCKLIST_PREVIOUSLY_CREATED_FILEPATH['score']
                        alert.RaiseFileAlertMetric(eventData, 'DELETE_EXTENSION_BLOCKLIST_PREVIOUSLY_CREATED_FILEPATH')
                    end

                    if globals.ENTROPY_REALLY_HIGH < v.entropy and eventData.currentExtensionData.lowEntropy then
                        if globals.EXTENSION_UNKNOWN == v.currentExtensionData.category then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST: ' ..
                                    globals.config
                                        .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST['score'])
                            eventData.alertScore = eventData.alertScore + globals.config
                                                       .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST')
                        end
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHEST: ' ..
                                globals.config
                                    .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHEST['score'])
                        eventData.alertScore = eventData.alertScore + globals.config
                                                   .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHEST['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHEST')
                    elseif globals.ENTROPY_VERY_HIGH < v.entropy and eventData.currentExtensionData.lowEntropy then
                        if globals.EXTENSION_UNKNOWN == v.currentExtensionData.category then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER: ' ..
                                    globals.config
                                        .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER['score'])
                            eventData.alertScore = eventData.alertScore + globals.config
                                                       .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER')
                        end
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHER: ' ..
                                globals.config
                                    .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHER['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHER['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGHER')
                    elseif globals.ENTROPY_HIGH < v.entropy and eventData.currentExtensionData.lowEntropy then
                        if globals.EXTENSION_UNKNOWN == v.currentExtensionData.category then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH: ' ..
                                    globals.config
                                        .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH')
                        end
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGH: ' ..
                                globals.config
                                    .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGH['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGH['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'DELETE_EXTENSION_KNOWN_WITH_LOW_ENTROPY_WITH_PREVIOUSLY_CREATED_SUBSTRING_POSSIBLE_MISMATCH_ENTROPY_HIGH')
                    elseif globals.ENTROPY_STATUS_REALLY_HIGH == v.entropyStatus then
                        if globals.EXTENSION_UNKNOWN == v.currentExtensionData.category then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST: ' ..
                                    globals.config
                                        .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHEST')
                        end
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHEST: ' ..
                                globals.config.DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHEST['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHEST['score']
                        alert.RaiseFileAlertMetric(eventData, 'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHEST')
                    elseif globals.ENTROPY_STATUS_VERY_HIGH == v.entropyStatus then
                        if globals.EXTENSION_UNKNOWN == v.currentExtensionData.category then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER: ' ..
                                    globals.config
                                        .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGHER')
                        end
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHER: ' ..
                                globals.config.DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHER['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHER['score']
                        alert.RaiseFileAlertMetric(eventData, 'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGHER')
                    elseif globals.ENTROPY_STATUS_HIGH == v.entropyStatus then
                        if globals.EXTENSION_UNKNOWN == v.currentExtensionData.category then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH: ' ..
                                    globals.config
                                        .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN_ENTROPY_HIGH')
                        end
                        utils.DebugLog('ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGH: ' ..
                                           globals.config.DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGH['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config.DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGH['score']
                        alert.RaiseFileAlertMetric(eventData, 'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_ENTROPY_HIGH')
                    else
                        if globals.EXTENSION_UNKNOWN == v.currentExtensionData.category then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN: ' ..
                                    globals.config.DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING_EXTENSION_UNKNOWN')
                        end
                        utils.DebugLog('ALERT_SCORE_CHANGE: DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING: ' ..
                                           globals.config.DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config.DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING['score']
                        alert.RaiseFileAlertMetric(eventData, 'DELETE_WITH_PREVIOUSLY_CREATED_SUBSTRING')
                    end
                end

                break
            else
                subString = string.find(v.fileName, '^' .. eventData.fileName, nil, true)

                if nil ~= subString then
                    -- NOTE: commented out since currently unreliable
                    -- delete then recreated?
                end
            end

        elseif globals.FILE_CREATE_NEW == eventData.operation and globals.FILE_CREATE_NEW == v.operation and
            eventData.fileName == v.fileName then
            if eventData.entropy == v.entropy then
                -- NOTE: could potentially use this in the future for possibly
                -- detecting ransom note drops, but need to have hashes as well
                -- to determine equivalence.
            end

        elseif globals.FILE_CREATE_NEW == eventData.operation then
            local subString = string.find(eventData.filePath, v.filePath, nil, true)

            if nil ~= subString and globals.FILE_DELETE == v.operation then
                local noCreate = true

                for _, prevOperation in pairs(pathEventTable[v.filePath]) do
                    if globals.FILE_CREATE_NEW == prevOperation then
                        noCreate = false
                        utils.DebugLog('globals.FILE_CREATE_NEW == prevOperation')
                    end
                end

                if noCreate then
                    utils.DebugLog('created filePath contains previously deleted filePath as substring')
                    utils.DebugLog('v.filePath: ' .. v.filePath)
                    utils.DebugLog('eventData.filePath: ' .. eventData.filePath)

                    if eventData.headerMismatch then
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: CREATE_EXTENSION_KNOWN_HEADER_MISMATCH_WITH_PREVIOUSLY_DELETED_SUBSTRING: ' ..
                                globals.config.CREATE_EXTENSION_KNOWN_HEADER_MISMATCH_WITH_PREVIOUSLY_DELETED_SUBSTRING['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .CREATE_EXTENSION_KNOWN_HEADER_MISMATCH_WITH_PREVIOUSLY_DELETED_SUBSTRING['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'CREATE_EXTENSION_KNOWN_HEADER_MISMATCH_WITH_PREVIOUSLY_DELETED_SUBSTRING')
                    else
                        utils.DebugLog('no headerMismatch')
                    end

                    utils.DebugLog('eventData.fileExtension: ' .. eventData.fileExtension)

                    if not utils.TableHasKey(globals.extensionMap, eventData.fileExtension) then
                        if globals.ENTROPY_STATUS_REALLY_HIGH == eventData.entropyStatus then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHEST: ' ..
                                    globals.config.CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHEST['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHEST['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHEST')
                        elseif globals.ENTROPY_STATUS_VERY_HIGH == eventData.entropyStatus then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHER: ' ..
                                    globals.config.CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHER['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHER['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGHER')
                        elseif globals.ENTROPY_STATUS_HIGH == eventData.entropyStatus then
                            utils.DebugLog(
                                'ALERT_SCORE_CHANGE: CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGH: ' ..
                                    globals.config.CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGH['score'])
                            eventData.alertScore = eventData.alertScore +
                                                       globals.config
                                                           .CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGH['score']
                            alert.RaiseFileAlertMetric(eventData,
                                'CREATE_WITH_PREVIOUSLY_DELETED_FILEPATH_SUBSTRING_ENTROPY_HIGH')
                        end
                    end

                    break
                end
            end
        end
    end
end

-- HeaderCheck is a wrapper over the HeaderComparison function. It performs some
-- sanity checks and filtering of MS office lock files.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return void.
function Ransomware:HeaderCheck(eventData, processData)
    if nil == next(eventData.headerBytes) then
        return
    end

    if eventData.officeLockFile then
        utils.DebugLog('office lock file skip header check: ' .. eventData.filePath)
        return
    end

    eventData.headerMismatch = self.HeaderComparison(eventData, processData, eventData.currentExtensionData)
    utils.DebugLog('eventData.headerMismatch: ' .. tostring(eventData.headerMismatch))

    if globals.FILE_RENAME == eventData.operation and eventData.filePreviousExtension ~= eventData.fileExtension then
        eventData.previousHeaderMismatch =
            self.HeaderComparison(eventData, processData, eventData.previousExtensionData)
        utils.DebugLog('eventData.previousHeaderMismatch: ' .. tostring(eventData.previousHeaderMismatch))
    end
end

-- Compares the file header to expected magic byte sequences (if they exist)
-- pertaining to its file extension. If sequences exist but no suitable match is
-- found, this anomaly is accounted for and will affect scoring.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @param extensionData: A table containing extension data.
-- @return boolean: True when the a header mismatch is found. False otherwise.
function Ransomware.HeaderComparison(eventData, processData, extensionData)
    local headerMismatch = false

    if nil == extensionData then
        return headerMismatch
    end

    if #extensionData.magicBytes == 0 then
        return headerMismatch
    end

    local magicBytesTable = extensionData.magicBytes
    table.insert(magicBytesTable, globals.t_null_1)
    table.insert(magicBytesTable, globals.t_xml_1)

    for _, v in pairs(magicBytesTable) do
        headerMismatch = false
        local bar = table.move(v, 1, 16, 1, {})
        local subHeader = table.move(eventData.headerBytes, 1, #v, 1, {})

        -- byte by byte comparison of header with known magic byte sequence
        for k4, v4 in pairs(subHeader) do
            -- utils.DebugLog('subHeader: ' .. v4 .. ' | compare: ' .. bar[k4])
            if v4 ~= bar[k4] then
                headerMismatch = true
                break
            end
        end

        if false == headerMismatch then
            break
        end
    end

    if true == headerMismatch then
        alert.RaiseFileAlertMetric(eventData, 'HEADER_MISMATCH')
    end

    -- If the file doesn't match its expected magic byte sequence, the ProcessData object will
    -- be checked to determine if any previous mismatches have occurred. Once the number of
    -- unique extensions modified meets / exceeds EXTENSION_HEADER_MISMATCH_THRESHOLD,
    -- subsequent mismatches will affect the process alert score (prior mismatches will not)
    -- NOTE: this is now explicitly enforced in TotalIndividualScore

    local fileExtension = ''

    if extensionData == eventData.currentExtensionData then
        fileExtension = eventData.fileExtension
    else
        fileExtension = eventData.filePreviousExtension
    end

    if headerMismatch then
        if not utils.TableHasKey(processData.headerMismatchExtensions, fileExtension) then
            processData.headerMismatchExtensions[fileExtension] = 0
            utils.DebugLog('NEW EXTENSION HEADER MISMATCH: ' .. fileExtension)
            processData.numHeaderMismatchExtensions = processData.numHeaderMismatchExtensions + 1
        end

        processData.headerMismatchExtensions[fileExtension] = processData.headerMismatchExtensions[fileExtension] + 1
    end

    return headerMismatch
end

-- EntropyCheck is a wrapper over the EntropyComparison function. It performs
-- two entropy comparisons checks; the first one on the extension data of
-- the current event, and the second one on the extension data of original
-- extension data before the rename operation took place.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return void.
function Ransomware:EntropyCheck(eventData, processData)
    eventData.entropyStatus = self:EntropyComparison(eventData, processData, eventData.fileExtension,
        eventData.currentExtensionData)

    if globals.FILE_RENAME == eventData.operation and eventData.filePreviousExtension ~= eventData.fileExtension then
        eventData.previousEntropyStatus = self:EntropyComparison(eventData, processData,
            eventData.filePreviousExtension, eventData.previousExtensionData)
    end
end

-- EntropyComparison evaluates the entropy of a (portion) of the file against
-- a range of predefined entropy values. When an entropy is found to be high,
-- it raises a file alert metric.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @param fileExtension string: The name of the extension.
-- @param extensionData: A table containing extension data.
-- @return integer: An integer representing the entropy status.
function Ransomware:EntropyComparison(eventData, processData, fileExtension, extensionData)
    local entropyStatus = globals.ENTROPY_STATUS_DEFAULT
    local entropyString = 'ENTROPY_DEFAULT'

    if globals.EXTENSION_IGNORED == extensionData.category then
        return entropyStatus
    end

    if globals.ENTROPY_REALLY_HIGH < eventData.entropy then
        if extensionData.lowEntropy then
            -- Extension is typically low entropy; alert signifies it exceeded its range.
            entropyString = 'ENTROPY_MISMATCH_REALLY_HIGH'
            entropyStatus = globals.ENTROPY_STATUS_MISMATCH_REALLY_HIGH
            self.EntropyMismatch(processData, fileExtension)
        else
            entropyString = 'ENTROPY_REALLY_HIGH'
            entropyStatus = globals.ENTROPY_STATUS_REALLY_HIGH
        end
    elseif globals.ENTROPY_VERY_HIGH < eventData.entropy then
        if extensionData.lowEntropy then
            -- Extension is typically low entropy; alert signifies it exceeded its range.
            entropyString = 'ENTROPY_MISMATCH_VERY_HIGH'
            entropyStatus = globals.ENTROPY_STATUS_MISMATCH_VERY_HIGH
            self.EntropyMismatch(processData, fileExtension)
        else
            entropyString = 'ENTROPY_VERY_HIGH'
            entropyStatus = globals.ENTROPY_STATUS_VERY_HIGH
        end
    elseif globals.ENTROPY_HIGH < eventData.entropy then
        entropyString = 'ENTROPY_HIGH'
        entropyStatus = globals.ENTROPY_STATUS_HIGH
    end

    if 'ENTROPY_DEFAULT' ~= entropyString then
        alert.RaiseFileAlertMetric(eventData, entropyString)
    end

    return entropyStatus
end

-- EntropyMismatch keeps track of the mismatched extensions per process.
-- @param processData table: A table containing process data.
-- @param fileExtension string: The name of the extension.
-- @return integer: An integer representing the new number of mismatched extensions
-- for the given extension in the current process.
function Ransomware.EntropyMismatch(processData, fileExtension)
    if not utils.TableHasKey(processData.entropyMismatchExtensions, fileExtension) then
        processData.entropyMismatchExtensions[fileExtension] = 0
        utils.DebugLog('NEW ENTROPY MISMATCH EXTENSION: ' .. fileExtension)
        processData.numEntropyMismatchExtensions = processData.numEntropyMismatchExtensions + 1
    end

    utils.DebugLog('ENTROPY MISMATCH EXTENSION: ' .. fileExtension)
    processData.entropyMismatchExtensions[fileExtension] = processData.entropyMismatchExtensions[fileExtension] + 1
    return processData.entropyMismatchExtensions[fileExtension]
end

-- RenameCheck examines the transition of the extension during a rename operation.
-- For example: transitioning from a known extension to a ransomware extension.
-- @param eventData table: A table containing event data.
-- @return integer: An integer representing the rename transition.
function Ransomware:RenameCheck(eventData)
    local previousExtensionKnown = false
    local currentExtensionSuspicious = self.IsRansomExtension(eventData)

    if utils.TableHasKey(globals.extensionMap, eventData.filePreviousExtension) then
        previousExtensionKnown = true
    end

    local currentExtensionKnown = false

    if utils.TableHasKey(globals.extensionMap, eventData.fileExtension) then
        currentExtensionKnown = true
    end

    local renameString = 'DEFAULT_RENAME'

    if previousExtensionKnown and currentExtensionSuspicious then
        eventData.renameTransition = globals.KNOWN_TO_SUSPICIOUS
        renameString = 'KNOWN_TO_SUSPICIOUS'
    elseif previousExtensionKnown and not currentExtensionKnown then
        eventData.renameTransition = globals.KNOWN_TO_UNKNOWN
        renameString = 'KNOWN_TO_UNKNOWN'
    elseif previousExtensionKnown and '' == eventData.fileExtension then
        eventData.renameTransition = globals.KNOWN_TO_BLANK
        renameString = 'KNOWN_TO_BLANK'
    elseif not previousExtensionKnown and currentExtensionSuspicious then
        eventData.renameTransition = globals.UNKNOWN_TO_SUSPICIOUS
        renameString = 'UNKNOWN_TO_SUSPICIOUS'
    elseif not previousExtensionKnown and not currentExtensionKnown then
        eventData.renameTransition = globals.UNKNOWN_TO_UNKNOWN
        renameString = 'UNKNOWN_TO_UNKNOWN'
    end

    if 'DEFAULT_RENAME' ~= renameString then
        alert.RaiseFileAlertMetric(eventData, renameString)
    end

    return eventData.renameTransition
end

-- AbnormalExtensionCheck performs various heuristics over the sub parts
-- of a file extension. It iterates over the sub-extensions and examines how
-- they relate to the final extension. For example, a common scenario is when
-- the sub-extension is known and the final extension is unknown.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return void.
function Ransomware.AbnormalExtensionCheck(eventData, processData)
    -- TODO: Are all renames made to the same extension format? If we could
    -- establish that activity across the board that would be strong proof of a
    -- process-wide pattern.

    -- Are there multiple extensions?
    -- Are one or more extensions legitimate? is the final extension unknown / suspicious?

    -- This regex will split the string based on the first instance of '.' and
    -- return the second string: e.g. sample.txt.doc ==> txt.doc
    local longExtension = eventData.fileName:match('%.(.*)')

    if longExtension == nil or longExtension == eventData.fileExtension then
        return
    end

    utils.DebugLog('fileExtension: ' .. eventData.fileExtension .. ' | longExtension: ' .. longExtension)
    eventData.multipleExtension = true

    -- This regex will split the string based on each instance of '.' in
    -- order to iterate through each 'subextension' of the original filename
    -- e.g. txt.doc.encrypted ==> {txt, doc, encrypted}
    for word in string.gmatch(longExtension, '([^%.]+)') do
        utils.DebugLog('WORD FOUND IN LONG EXTENSION: ' .. word)

        if word == eventData.fileExtension then
            goto continue
        end

        if not utils.TableHasKey(processData.longExtensions, word) then
            processData.longExtensions[word] = 1
        else
            processData.longExtensions[word] = processData.longExtensions[word] + 1
        end

        if utils.TableHasKey(globals.extensionMap, string.lower(word)) then
            utils.DebugLog('SUBEXTENSION_KNOWN: ' .. word)
            utils.DebugLog('ALERT_SCORE_CHANGE: SUBEXTENSION_KNOWN: ' .. globals.config.SUBEXTENSION_KNOWN['score'])
            eventData.alertScore = eventData.alertScore + globals.config.SUBEXTENSION_KNOWN['score']
            alert.RaiseFileAlertMetric(eventData, 'SUBEXTENSION_KNOWN')

            if globals.FILE_CREATE_NEW == eventData.operation and globals.EXTENSION_UNKNOWN ==
                eventData.currentExtensionData.category then
                utils.DebugLog('CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN: ' .. word)
                utils.DebugLog('ALERT_SCORE_CHANGE: CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN: ' ..
                                   globals.config.CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN['score'])
                eventData.alertScore = eventData.alertScore +
                                           globals.config.CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN['score']
                alert.RaiseFileAlertMetric(eventData, 'CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN')

                if not utils.TableHasKey(processData.subExtensions, word) then
                    processData.subExtensions[word] = 0
                    utils.DebugLog('NEW subextension: ' .. word)
                end

                processData.subExtensions[word] = processData.subExtensions[word] + 1

                local totalSubs = 0
                local totalUniqueSubs = 0

                for _, v in pairs(processData.subExtensions) do
                    totalSubs = totalSubs + v
                    totalUniqueSubs = totalUniqueSubs + 1
                end

                utils.DebugLog('Unique sub-extensions: ' .. totalUniqueSubs .. ' | total entries: ' .. totalSubs)

                if 4 < totalUniqueSubs and 100 < totalSubs then
                    utils.DebugLog('ALERT_SCORE_CHANGE #2.1')

                    if globals.ENTROPY_STATUS_REALLY_HIGH == eventData.entropyStatus then
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHEST: ' ..
                                globals.config.CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHEST['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHEST['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHEST')
                    elseif globals.ENTROPY_STATUS_VERY_HIGH == eventData.entropyStatus then
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHER: ' ..
                                globals.config.CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHER['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHER['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGHER')
                    elseif globals.ENTROPY_STATUS_HIGH == eventData.entropyStatus then
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGH: ' ..
                                globals.config.CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGH['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGH['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_HIGH')
                    else
                        utils.DebugLog(
                            'ALERT_SCORE_CHANGE: CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_AVERAGE: ' ..
                                globals.config.CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_AVERAGE['score'])
                        eventData.alertScore = eventData.alertScore +
                                                   globals.config
                                                       .CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_AVERAGE['score']
                        alert.RaiseFileAlertMetric(eventData,
                            'CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_AVERAGE')
                    end

                    -- for k,v in pairs (processData.subExtensions) do
                    --    utils.DebugLog(k .. ': ' .. v)
                    -- end

                    -- if 4 < #processData.deleteExtensions then
                    --    eventData.alertScore = eventData.alertScore + 0.5
                    -- else
                    --    eventData.alertScore = eventData.alertScore + 0.005
                    -- end

                    -- alert.RaiseFileAlertMetric(eventData, 'CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_THRESHOLD_ENTROPY_AVERAGE')
                end

                if utils.TableHasKey(processData.deleteExtensions, word) then
                    utils.DebugLog(
                        'ALERT_SCORE_CHANGE: CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED: ' ..
                            globals.config.CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED['score'])
                    eventData.alertScore = eventData.alertScore +
                                               globals.config
                                                   .CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED['score']
                    alert.RaiseFileAlertMetric(eventData,
                        'CREATE_EXTENSION_UNKNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED')
                end

            elseif globals.FILE_CREATE_NEW == eventData.operation then
                utils.DebugLog('ALERT_SCORE_CHANGE: CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN: ' ..
                                   globals.config.CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN['score'])
                eventData.alertScore = eventData.alertScore +
                                           globals.config.CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN['score']
                alert.RaiseFileAlertMetric(eventData, 'CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN')

                if utils.TableHasKey(processData.deleteExtensions, word) then
                    utils.DebugLog(
                        'ALERT_SCORE_CHANGE: CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED: ' ..
                            globals.config.CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED['score'])
                    eventData.alertScore = eventData.alertScore +
                                               globals.config
                                                   .CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED['score']
                    alert.RaiseFileAlertMetric(eventData,
                        'CREATE_EXTENSION_KNOWN_SUBEXTENSION_KNOWN_AND_PREVIOUSLY_DELETED')
                end

            elseif globals.EXTENSION_UNKNOWN == eventData.currentExtensionData.category then
                utils.DebugLog('ALERT_SCORE_CHANGE: SUBEXTENSION_KNOWN_EXTENSION_UNKNOWN: ' ..
                                   globals.config.SUBEXTENSION_KNOWN_EXTENSION_UNKNOWN['score'])
                eventData.alertScore = eventData.alertScore +
                                           globals.config.SUBEXTENSION_KNOWN_EXTENSION_UNKNOWN['score']
                alert.RaiseFileAlertMetric(eventData, 'SUBEXTENSION_KNOWN_EXTENSION_UNKNOWN')
            end

            -- Maybe also check entropy and header mismatches here?
            -- Also check if this extension has also been deleted!

        else
            for k, _ in pairs(processData.deleteExtensions) do
                if word == k then
                    utils.DebugLog('SUBEXTENSION_UNKNOWN_AND_PREVIOUSLY_DELETED' .. k)
                    utils.DebugLog('ALERT_SCORE_CHANGE: SUBEXTENSION_UNKNOWN_AND_PREVIOUSLY_DELETED: ' ..
                                       globals.config.SUBEXTENSION_UNKNOWN_AND_PREVIOUSLY_DELETED['score'])
                    eventData.alertScore = eventData.alertScore +
                                               globals.config.SUBEXTENSION_UNKNOWN_AND_PREVIOUSLY_DELETED['score']
                    alert.RaiseFileAlertMetric(eventData, 'SUBEXTENSION_UNKNOWN_AND_PREVIOUSLY_DELETED')
                end
            end
        end

        ::continue::
    end
end

-- CanaryCheck is a wrapper over the Lua_CanaryCheck function. It raises a file
-- alert metric and generates an alert when a file event targets our planted
-- canary files.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return boolean: True when a canary activity is seen. False otherwise.
function Ransomware:CanaryCheck(eventData, processData)
    -- CanaryCheck limits file creation alerts to globals.CANARY_CREATE_FILE_ALERT_CAP.
    if true == globals.Lua_CanaryCheck(eventData) then
        table.insert(processData.events, eventData)
        if self.diagnosticMode then
            processData.beta_alert = true
        end
        processData.canary_alert = true

        alert.RaiseFileAlertMetric(eventData, 'CANARY_ACTIVITY')

        -- Update the process extension table (for debugging / display purposes only).
        globals.UpdateExtensionTables(eventData, processData)

        alert.GenerateAlert(processData, self.diagnosticMode)
        return true
    end
    return false
end

-- Verifies if the extension of the current file event belongs to known ransomware
-- family. When it finds so, it raises a file alert metric.
-- @param eventData table: A table containing event data.
-- @returns boolean: True if the current file events has a ransomware extension,
-- False otherwise.
function Ransomware.IsRansomExtension(eventData)
    if globals.EXTENSION_SUSPICIOUS == eventData.currentExtensionData.category then
        alert.RaiseFileAlertMetric(eventData, 'RANSOM_EXTENSION')
        return true
    end

    return false
end

-- RansomNoteCheck checks for ransom notes dropped by ransomware. Currently,
-- this check only looks at the filename rather than the file content.
-- @param processData table: A table containing process data.
-- @return void.
function Ransomware.RansomNoteCheck(processData)
    -- List of suspicious words seen in ransom note filenames.
    local suspiciousWords = {
        'crypt',
        'lock',
        'help',
        'save',
        'recover',
        'restore',
        'return',
        'read',
        'repair',
        'instruction',
        'attention',
        'files',
        'coin',
        'vault',
        'how',
        'pay',
        'please',
        'back',
        'worry'
    }

    -- List of suspicious extensions seen in ransom notes.
    local suspiciousExts = {'txt', 'hta', 'rtf', 'png', 'jpg', 'bmp', 'htm', 'html'}

    local calculateTrendScore = function(mostCreatedFileName, countOfFiles)
        -- lower case the file name and extension.
        -- ToDo: replace some characters used to bypass file name matching :
        -- cerber: _R_E_A_D___T_H_I_S___[]_.hta
        local fileName = mostCreatedFileName:lower()
        local extension = processData.createFileNames[mostCreatedFileName][1].fileExtension:lower()

        -- [1] check if the file name contains any of the suspicious words.
        local suspiciousWordCount = 0
        for _, suspiciousWord in pairs(suspiciousWords) do
            local match = string.find(fileName, suspiciousWord, nil, true)
            if match then
                suspiciousWordCount = suspiciousWordCount + 1
            end
        end

        -- [2] check if the file name contains a suspicious extension.
        local suspiciousExtension = 0
        local suspiciousExtensionName = nil
        for _, suspiciousExt in pairs(suspiciousExts) do
            if suspiciousExt == extension then
                suspiciousExtension = 1
                suspiciousExtensionName = extension
                break
            end
        end

        -- [3] check if the file has been seen in locations that serve different responsibilities.
        local uniqueDirectoriesByResponsibility = {}
        local uniqueDirectoriesByResponsibilityCount = 0
        for _, fileNameTable in pairs(processData.createFileNames[mostCreatedFileName]) do
            local normalizedPath = utils.NormalizePath(fileNameTable.filePath)
            if not utils.TableHasValue(uniqueDirectoriesByResponsibility, normalizedPath) then
                table.insert(uniqueDirectoriesByResponsibility, normalizedPath)
                uniqueDirectoriesByResponsibilityCount = uniqueDirectoriesByResponsibilityCount + 1
            end
        end
        if uniqueDirectoriesByResponsibilityCount > 0 then
            uniqueDirectoriesByResponsibilityCount = #uniqueDirectoriesByResponsibility - 1
        end

        -- if we fail to meet any of the criteria below, the trendScore will be
        -- equal to zero (because the values are multiplied):
        -- 1. suspicious extension.
        -- 2. suspicious word in the filename.
        -- 3. more than one file path in terms of responsibility has been touched.
        -- 4. the number of files created with this filename must be three or more
        -- (enforced before calculateTrendScore is invoked).
        local trendScore = 0.0
        trendScore = suspiciousWordCount * suspiciousExtension * uniqueDirectoriesByResponsibilityCount * countOfFiles
        if trendScore == 0 then
            return trendScore
        end

        -- [5] print some debug logs.
        utils.DebugLog(mostCreatedFileName .. ' was created ' .. countOfFiles .. ' times')
        if suspiciousWordCount > 0 then
            utils.DebugLog(mostCreatedFileName .. ' contains ' .. suspiciousWordCount .. ' suspicious word(s)')
        end
        if suspiciousExtension > 0 then
            utils.DebugLog(mostCreatedFileName .. ' contains a suspicious extension: ' .. suspiciousExtensionName)
        end
        if uniqueDirectoriesByResponsibilityCount > 0 then
            utils.DebugLog(mostCreatedFileName .. ' was created in directories that serve different responsibilities: ')
            utils.PrintTable(uniqueDirectoriesByResponsibility)
        end

        utils.DebugLog('ransom note detection trend score: ' .. trendScore)
        return trendScore
    end

    -- Walk over created files and calculate the trend score for each set of
    -- created file names. To have a deterministic and consistent result across
    -- multiple runs, we choose the maximum score value calculated.
    local trendScore = 0.0
    local countOfFiles = 0
    local mostCreatedFileName = nil
    local maxTrendSCore = 0.0
    for fileName, fileNameTable in pairs(processData.createFileNames) do
        -- We require at last 3 files to keep processing.
        if #processData.createFileNames[fileName] >= 3 then
            countOfFiles = #fileNameTable
            mostCreatedFileName = fileName
            trendScore = calculateTrendScore(mostCreatedFileName, countOfFiles)
            if trendScore > maxTrendSCore then
                maxTrendSCore = trendScore
            end
        end
    end

    processData.trendScore = processData.trendScore + maxTrendSCore

end

-- TotalIndividualScore tallies up the score for this file event after all checks
-- are made. A file alert metric is raised when any of the following conditions
-- are met:
-- 1) When a header or entropy mismatch threshold is reached.
-- 2) When a ransomware extension is found.
-- 3) In a rename operation, the previous file path has a high entropy mismatch
--    or a rename transition is found.
-- 4) When abnormal extension characters are found.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return void.
function Ransomware:TotalIndividualScore(eventData, processData)
    if processData.numHeaderMismatchExtensions > 0 then
        utils.DebugLog('processData.numHeaderMismatchExtensions: ' .. processData.numHeaderMismatchExtensions)
    end

    if eventData.headerMismatch then
        if globals.HEADER_MISMATCH_THRESHOLD <= processData.numHeaderMismatchExtensions then
            utils.DebugLog('processData.numHeaderMismatchExtensions: ' .. processData.numHeaderMismatchExtensions)
            utils.DebugLog('ALERT_SCORE_CHANGE: HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET: ' ..
                               (globals.config.HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET['score'] *
                                   processData.numHeaderMismatchExtensions))
            eventData.alertScore = eventData.alertScore +
                                       (globals.config.HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET['score'] *
                                           processData.numHeaderMismatchExtensions)
            alert.RaiseFileAlertMetric(eventData, 'HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET')
        end
    elseif eventData.previousHeaderMismatch then
        if globals.HEADER_MISMATCH_THRESHOLD <= processData.numHeaderMismatchExtensions then
            utils.DebugLog('processData.numHeaderMismatchExtensions: ' .. processData.numHeaderMismatchExtensions)
            utils.DebugLog('ALERT_SCORE_CHANGE: PREVIOUS_HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET: ' ..
                               (globals.config.PREVIOUS_HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET['score'] *
                                   processData.numHeaderMismatchExtensions))
            eventData.alertScore = eventData.alertScore +
                                       (globals.config.PREVIOUS_HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET['score'] *
                                           processData.numHeaderMismatchExtensions)
            alert.RaiseFileAlertMetric(eventData, 'PREVIOUS_HEADER_MISMATCH_EXTENSIONS_THRESHOLD_MET')
        end
    end

    if globals.ENTROPY_STATUS_MISMATCH_REALLY_HIGH == eventData.entropyStatus then
        if globals.ENTROPY_MISMATCH_THRESHOLD <= processData.numEntropyMismatchExtensions then
            utils.DebugLog('ALERT_SCORE_CHANGE: ENTROPY_MISMATCH_HIGHEST: ' ..
                               (globals.config.ENTROPY_MISMATCH_HIGHEST['score'] *
                                   processData.numHeaderMismatchExtensions))
            eventData.alertScore = eventData.alertScore +
                                       (globals.config.ENTROPY_MISMATCH_HIGHEST['score'] *
                                           processData.numEntropyMismatchExtensions)
            alert.RaiseFileAlertMetric(eventData, 'ENTROPY_MISMATCH_HIGHEST')

            if eventData.headerMismatch then
                utils.DebugLog('ALERT_SCORE_CHANGE: ENTROPY_MISMATCH_HIGHEST_WITH_HEADER_MISMATCH: ' ..
                                   globals.config.ENTROPY_MISMATCH_HIGHEST_WITH_HEADER_MISMATCH['score'])
                eventData.alertScore = eventData.alertScore +
                                           globals.config.ENTROPY_MISMATCH_HIGHEST_WITH_HEADER_MISMATCH['score']
                alert.RaiseFileAlertMetric(eventData, 'ENTROPY_MISMATCH_HIGHEST_WITH_HEADER_MISMATCH')
            end
        end
    elseif globals.ENTROPY_STATUS_MISMATCH_VERY_HIGH == eventData.entropyStatus then
        if globals.ENTROPY_MISMATCH_THRESHOLD <= processData.numEntropyMismatchExtensions then
            utils.DebugLog('ALERT_SCORE_CHANGE: ENTROPY_MISMATCH_HIGHER: ' ..
                               (globals.config.ENTROPY_MISMATCH_HIGHER['score'] *
                                   processData.numEntropyMismatchExtensions))
            eventData.alertScore = eventData.alertScore +
                                       (globals.config.ENTROPY_MISMATCH_HIGHER['score'] *
                                           processData.numEntropyMismatchExtensions)
            alert.RaiseFileAlertMetric(eventData, 'ENTROPY_MISMATCH_HIGHER')

            if eventData.headerMismatch then
                utils.DebugLog('ALERT_SCORE_CHANGE: ENTROPY_MISMATCH_HIGHER_WITH_HEADER_MISMATCH: ' ..
                                   globals.config.ENTROPY_MISMATCH_HIGHER_WITH_HEADER_MISMATCH['score'])
                eventData.alertScore = eventData.alertScore +
                                           globals.config.ENTROPY_MISMATCH_HIGHER_WITH_HEADER_MISMATCH['score']
                alert.RaiseFileAlertMetric(eventData, 'ENTROPY_MISMATCH_HIGHER_WITH_HEADER_MISMATCH')
            end
        end
    elseif globals.ENTROPY_STATUS_VERY_HIGH == eventData.entropyStatus then
        utils.DebugLog('ALERT_SCORE_CHANGE: ENTROPY_HIGHER: ' .. globals.config.ENTROPY_HIGHER['score'])
        eventData.alertScore = eventData.alertScore + globals.config.ENTROPY_HIGHER['score']
        alert.RaiseFileAlertMetric(eventData, 'ENTROPY_HIGHER')

        if not utils.TableHasKey(globals.extensionMap, eventData.fileExtension) then
            utils.DebugLog('ALERT_SCORE_CHANGE: ENTROPY_HIGHER_EXTENSION_UNKNOWN: ' ..
                               globals.config.ENTROPY_HIGHER_EXTENSION_UNKNOWN['score'])
            eventData.alertScore = eventData.alertScore + globals.config.ENTROPY_HIGHER_EXTENSION_UNKNOWN['score']
            alert.RaiseFileAlertMetric(eventData, 'ENTROPY_HIGHER_EXTENSION_UNKNOWN')
        end
    end

    if self.IsRansomExtension(eventData) then
        utils.DebugLog('ALERT_SCORE_CHANGE: EXTENSION_BLOCKLIST: ' .. globals.config.EXTENSION_BLOCKLIST['score'])
        eventData.alertScore = eventData.alertScore + globals.config.EXTENSION_BLOCKLIST['score']
        alert.RaiseFileAlertMetric(eventData, 'EXTENSION_BLOCKLIST')
    end

    if globals.FILE_RENAME == eventData.operation then
        if globals.ENTROPY_STATUS_MISMATCH_REALLY_HIGH == eventData.previousEntropyStatus then
            utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_ENTROPY_MISMATCH_HIGHEST: ' ..
                               (globals.config.RENAME_ENTROPY_MISMATCH_HIGHEST['score'] *
                                   processData.numEntropyMismatchExtensions))
            eventData.alertScore = eventData.alertScore +
                                       (globals.config.RENAME_ENTROPY_MISMATCH_HIGHEST *
                                           processData.numEntropyMismatchExtensions)
            alert.RaiseFileAlertMetric(eventData, 'RENAME_ENTROPY_MISMATCH_HIGHEST')

        elseif globals.ENTROPY_STATUS_MISMATCH_VERY_HIGH == eventData.previousEntropyStatus then
            utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_ENTROPY_MISMATCH_HIGHER: ' ..
                               (globals.config.RENAME_ENTROPY_MISMATCH_HIGHER['score'] *
                                   processData.numEntropyMismatchExtensions))
            eventData.alertScore = eventData.alertScore +
                                       (globals.config.RENAME_ENTROPY_MISMATCH_HIGHER['score'] *
                                           processData.numEntropyMismatchExtensions)
            alert.RaiseFileAlertMetric(eventData, 'RENAME_ENTROPY_MISMATCH_HIGHER')
        end

        -------------------------------------------------------------------

        if globals.KNOWN_TO_SUSPICIOUS == eventData.renameTransition then
            utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_EXTENSION_KNOWN_TO_BLOCKLIST: ' ..
                               globals.config.RENAME_EXTENSION_KNOWN_TO_BLOCKLIST['score'])
            eventData.alertScore = eventData.alertScore + globals.config.RENAME_EXTENSION_KNOWN_TO_BLOCKLIST['score']
            alert.RaiseFileAlertMetric(eventData, 'RENAME_EXTENSION_KNOWN_TO_BLOCKLIST')
        elseif globals.KNOWN_TO_UNKNOWN == eventData.renameTransition then
            if eventData.multipleExtension then
                utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_EXTENSION_KNOWN_TO_UNKNOWN_MULTIPLE: ' ..
                                   globals.config.RENAME_EXTENSION_KNOWN_TO_UNKNOWN_MULTIPLE['score'])
                eventData.alertScore = eventData.alertScore +
                                           globals.config.RENAME_EXTENSION_KNOWN_TO_UNKNOWN_MULTIPLE['score']
                alert.RaiseFileAlertMetric(eventData, 'RENAME_EXTENSION_KNOWN_TO_UNKNOWN_MULTIPLE')
            else
                utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_EXTENSION_KNOWN_TO_UNKNOWN: ' ..
                                   globals.config.RENAME_EXTENSION_KNOWN_TO_UNKNOWN['score'])
                eventData.alertScore = eventData.alertScore + globals.config.RENAME_EXTENSION_KNOWN_TO_UNKNOWN['score']
                alert.RaiseFileAlertMetric(eventData, 'RENAME_EXTENSION_KNOWN_TO_UNKNOWN')
            end

            local subString = string.find(eventData.filePath, eventData.filePreviousPath, nil, true)

            if nil ~= subString then
                utils.DebugLog('filePreviousPath found in filePath!')

                if not utils.TableHasKey(processData.appendedPaths, eventData.filePreviousExtension) then
                    processData.appendedPaths[eventData.filePreviousExtension] = 0
                end

                processData.appendedPaths[eventData.filePreviousExtension] =
                    processData.appendedPaths[eventData.filePreviousExtension] + 1

                for k, v in pairs(processData.appendedPaths) do
                    utils.DebugLog(k .. ' | ' .. v)
                end

            end

        elseif globals.KNOWN_TO_BLANK == eventData.renameTransition then
            utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_EXTENSION_KNOWN_TO_BLANK: ' ..
                               globals.config.RENAME_EXTENSION_KNOWN_TO_BLANK['score'])
            eventData.alertScore = eventData.alertScore + globals.config.RENAME_EXTENSION_KNOWN_TO_BLANK['score']
            alert.RaiseFileAlertMetric(eventData, 'RENAME_EXTENSION_KNOWN_TO_BLANK')
        elseif globals.UNKNOWN_TO_SUSPICIOUS == eventData.renameTransition then
            utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_EXTENSION_UNKNOWN_TO_BLOCKLIST: ' ..
                               globals.config.RENAME_EXTENSION_UNKNOWN_TO_BLOCKLIST['score'])
            eventData.alertScore = eventData.alertScore + globals.config.RENAME_EXTENSION_UNKNOWN_TO_BLOCKLIST['score']
            alert.RaiseFileAlertMetric(eventData, 'RENAME_EXTENSION_UNKNOWN_TO_BLOCKLIST')
        elseif globals.UNKNOWN_TO_UNKNOWN == eventData.renameTransition then
            utils.DebugLog('ALERT_SCORE_CHANGE: RENAME_EXTENSION_UNKNOWN_TO_UNKNOWN: ' ..
                               globals.config.RENAME_EXTENSION_UNKNOWN_TO_UNKNOWN['score'])
            eventData.alertScore = eventData.alertScore + globals.config.RENAME_EXTENSION_UNKNOWN_TO_UNKNOWN['score']
            alert.RaiseFileAlertMetric(eventData, 'RENAME_EXTENSION_UNKNOWN_TO_UNKNOWN')
        end
    end

    -- TODO: Implement the numAbnormalExtensionCharacters check.
    if 0 < eventData.numAbnormalExtensionCharacters then
        utils.DebugLog('ALERT_SCORE_CHANGE: ABNORMAL_EXTENSION_CHARACTERS: ' ..
                           (globals.config.ABNORMAL_EXTENSION_CHARACTERS['score'] *
                               eventData.numAbnormalExtensionCharacters))
        eventData.alertScore = eventData.alertScore +
                                   (globals.config.ABNORMAL_EXTENSION_CHARACTERS['score'] *
                                       eventData.numAbnormalExtensionCharacters)
        alert.RaiseFileAlertMetric(eventData, 'ABNORMAL_EXTENSION_CHARACTERS')
    end
end

-- Appends child process data to the parentProcessData table. This is used in
-- the endpoint to include a list of suspicious child processes spawned by
-- ransomware within the parent alert under the 'Ransomware.child_processes'
-- ECS key. This function creates an alert for each individual child process and
-- appends them to an array. Currently, this is capped to add a max of five
-- children and *only* if their score is non-zero.
-- @param parentProcessData table: Table containing parent process data.
-- @param ransomwareChildProcesses table: Output table which child process alerts
-- will be appended to.
-- @return bool: Returns true on success and false on failure.
function Ransomware:AppendChildProcesses(parentProcessData, ransomwareChildProcesses)
    -- Sanity check input param
    if nil == parentProcessData then
        return false
    end

    -- Loop over children and create a mini alert for each one
    local counter = 0
    for k, _ in pairs(parentProcessData.children) do
        -- Check if we have exceed max child cap and break if so
        if counter >= globals.MAX_CHILD_PROCESSES then
            break
        end

        local childProcessData = self.processDataTable[k]
        -- Only add child if total score is non-zero
        if nil ~= childProcessData and 0.0 ~= childProcessData.totalScore then
            -- Copy over basic alert details
            local childProcessTable = {}
            childProcessTable.pid = childProcessData.processId
            childProcessTable.score = childProcessData.totalScore
            childProcessTable.alert_files = {}

            -- Create a mini alert for the specified child process data
            alert.GenerateElasticAlert(childProcessTable, childProcessData)

            -- Append alert to ransomwareChildProcesses array
            table.insert(ransomwareChildProcesses, childProcessTable)

            -- Increment counter
            counter = counter + 1
        end
    end

    return true
end


local Production = Ransomware:new({nameString = 'production', diagnosticMode = false})

-- Checks whether we want to extend the event threshold for a specific process.
-- Occasionally, ransomware will create/drop ransomware notes and start renaming
-- files *before* starting the encryption process. If this happens in the first
-- 200 events, there is a chance we will not see any file encryption behavior
-- and so fail to alert. This function performs basic heuristics on the given
-- file events and will return a decision as to whether the event threshold
-- should be extended for the given process. This function is essentially a
-- decision tree and looks for:
-- 1) A high proportion of create file events.
-- 2) If there are creates, then max 2 create extensions (e.g. .txt + .lock).
-- 3) If there are renames, then max 1 rename extensions (e.g. .lock).
-- 3) A large number of unique directories touched (e.g. dropping ransom notes across the file system).
-- 4) A reasonably high total score for current activity (NB CURRENTLY NOT IMPLEMENTED).
-- Hence, it is specifically looking for ransomware dropping ransom notes across the file system.
-- @param processData table: Table containing process data.
-- @return boolean: True to extend event threshold. False otherwise.
function Production.ExtendEventThresholdCheck(processData)
    -- [1] Calculate percent of creates for all current file events.
    -- NB This will be calculated at 200 *and* 400 file events (if required)
    -- to see if we want to extend the event threshold even further.
    local numberOfCreates = 0
    local numberOfCreateExtensions = 0
    local percentOfCreates = 0.0
    local numberOfRenames = 0
    local numberOfRenameExtensions = 0
    local uniqueDirectories = {}
    local totalUniqueDirectories = 0

    -- Calculate the percent of creates (and unique directories for later use).
    for _, fileEvents in pairs(processData.createExtensions) do
        numberOfCreateExtensions = numberOfCreateExtensions + 1
        numberOfCreates = numberOfCreates + #fileEvents
        for _, fileEvent in pairs(fileEvents) do
            -- This regex will split the file path based on the last instance of '\'
            -- and so will return the current directory of the file event.
            local currentDir = fileEvent.filePath:match('^(.*)\\')
            if not utils.TableHasKey(uniqueDirectories, currentDir) then
                uniqueDirectories[currentDir] = 1
                totalUniqueDirectories = totalUniqueDirectories + 1
            else
                uniqueDirectories[currentDir] = uniqueDirectories[currentDir] + 1
            end
        end
    end
    percentOfCreates = (numberOfCreates / #processData.events) * 100

    -- Calculate the number of renames.
    for _, fileEvents in pairs(processData.renameExtensions) do
        numberOfRenameExtensions = numberOfRenameExtensions + 1
        numberOfRenames = numberOfRenames + #fileEvents
    end

    -- If number of creates and renames are both zero then bail.
    if (numberOfRenames == 0 and numberOfCreates == 0) then
        return false
    end

    -- [2] If we have over 70% of the given file events being creates then carry
    -- on checking if we should extend the event threshold. This heuristic was
    -- generated via looking at the first 200 file events for a number of samples
    -- which immediately drop a number of ransom notes.
    -- (e.g. clop 70f42cc9fca43dc1fdfa584b37ecbc81761fb996cb358b6f569d734fa8cce4e3)
    -- NB If necessary in future this could be expanded to include samples which
    -- include a large number of renames within the first 200 events by checking
    -- if percentOfRenames >= 70 and whether some unique file threshold is reached
    -- (as this will not involve dropping files in loads of different dirs but
    -- rather modifying many in the same dir).
    if not (percentOfCreates >= 70) then
        return false
    end

    -- [3] If we have create file events, check we have at most 2 extensions. NB
    -- This should technically be at most 2 (e.g. ransom note + ransom extension)
    -- but ransomware sometimes drops binaries/other random stuff beforehand so
    -- this could be incremented in future (with risk of FPs).
    if (numberOfCreates ~= 0) then
        if not (numberOfCreateExtensions <= 2) then
            return false
        end
    end

    -- [4] If we have rename file events, check we only have 1 extension
    -- (e.g. ransom extension).
    if (numberOfRenames ~= 0) then
        if not (numberOfRenameExtensions == 1) then
            return false
        end
    end

    -- [5] How many directories has the process touched? If it has created files
    -- in over X directories it's probably suspicious. Normalization constant
    -- was tested via looking at a number of samples which ranged between 97-154
    -- unique dirs after 200 events.
    if not (totalUniqueDirectories >= (#processData.events / 2.2)) then
        return false
    end

    -- [6] If we reached this stage the process is suspicious enough to continue
    -- monitoring for a bit longer.
    utils.DebugLog('Extending Event Threshold for PID: ' .. processData.processId)
    return true
end

-- Anomalous file modification patterns can be found through comparing ratios
-- pertaining to the number of deletes, creates, renames, etc. observed within a
-- process along with ratios of any corresponding file extensions. One scenario
-- would be a file extension being involved in multiple rename events to different
-- unique extensions (e.g. file.crypt => file.txt; test.crypt => test.doc;
-- sample.crypt => sample.xls). This is useful for finding generic patterns
-- that may be easy to identify when a user manually inspects event logs, but may
-- be more difficult to determine as events are analyzed sequentially.
-- @param processData table: A table containing process data.
-- @return void.
function Production.TrendAnalysis(processData)
    -- uniformity in renames?
    local numRenames = 0
    local numRenameExtensions = 0
    local numRenamePreviousExtensions = 0

    for _, v in pairs(processData.renameExtensions) do
        numRenameExtensions = numRenameExtensions + 1
        numRenames = numRenames + #v
    end

    for _, _ in pairs(processData.renamePreviousExtensions) do
        numRenamePreviousExtensions = numRenamePreviousExtensions + 1
    end

    if 20 < numRenames and 0 < numRenameExtensions then
        local renameExtensionRatio = numRenamePreviousExtensions / numRenameExtensions
        utils.DebugLog('numRenames : ' .. numRenames .. ' | numRenameExtensions: ' .. numRenameExtensions ..
                           ' | numRenamePreviousExtensions: ' .. numRenamePreviousExtensions)

        if 2.0 < renameExtensionRatio then
            utils.DebugLog('Previous to Current Ratio > 2.0: ' .. renameExtensionRatio)
            -- NOTE: reduced weight 0.1 => 0.01
            utils.DebugLog('TREND_SCORE_CHANGE: TREND_SCORE_RENAME_EXTENSION_RATIO: ' ..
                               (globals.config.TREND_SCORE_RENAME_EXTENSION_RATIO['score'] * renameExtensionRatio))
            processData.trendScore = processData.trendScore +
                                         (globals.config.TREND_SCORE_RENAME_EXTENSION_RATIO['score'] *
                                             renameExtensionRatio)
            utils.DebugLog('TREND_SCORE_CHANGE: TREND_SCORE_NUM_RENAMES: ' ..
                               (globals.config.TREND_SCORE_NUM_RENAMES['score'] * numRenames))
            processData.trendScore = processData.trendScore +
                                         (globals.config.TREND_SCORE_NUM_RENAMES['score'] * numRenames)
        end

        if 1 == numRenamePreviousExtensions and 3 < numRenameExtensions then
            -- NOTE: changed weight by * 0.01
            renameExtensionRatio = (numRenameExtensions / numRenamePreviousExtensions) *
                                       globals.config.TREND_SCORE_SINGLE_PREV_RENAME_EXTENSION['score']
            processData.trendScore = processData.trendScore + renameExtensionRatio
            utils.DebugLog('TREND_SCORE_CHANGE: TREND_SCORE_SINGLE_PREV_RENAME_EXTENSION: ' .. renameExtensionRatio)
        end
    end

    ------------------------------------

    -- TODO: Look back at last ~20 modified; is there a discernible pattern?
    --  e.g. CREATE .tmp; DELETE .*, RENAME .tmp->.zip
    -- TODO: Is most everything created later renamed? To ZIP?

    -- uniformity in creates?
    local numCreates = 0
    local numCreateExtensions = 0

    for _, v in pairs(processData.createExtensions) do
        numCreateExtensions = numCreateExtensions + 1
        numCreates = numCreates + #v
    end

    local numDeletes = 0
    local numDeleteExtensions = 0

    for _, v in pairs(processData.deleteExtensions) do
        numDeleteExtensions = numDeleteExtensions + 1
        numDeletes = numDeletes + #v
    end

    local deleteCreateRatio = 0

    if 0 < numCreateExtensions then
        deleteCreateRatio = numDeleteExtensions / numCreateExtensions
        utils.DebugLog('deleteCreateRatio: ' .. deleteCreateRatio)

        if 1.0 <= deleteCreateRatio then
            -- NOTE: changed weight by * 0.01
            processData.trendScore = processData.trendScore +
                                         (deleteCreateRatio * globals.config.TREND_SCORE_DELETE_CREATE_RATIO['score'])
            utils.DebugLog('TREND_SCORE_CHANGE: TREND_SCORE_DELETE_CREATE_RATIO: ' ..
                               (deleteCreateRatio * globals.config.TREND_SCORE_DELETE_CREATE_RATIO['score']))

            if numCreates > numDeletes then
                processData.trendScore = processData.trendScore +
                                             globals.config.TREND_SCORE_MORE_CREATES_THAN_DELETES['score']
                utils.DebugLog('TREND_SCORE_CHANGE: TREND_SCORE_MORE_CREATES_THAN_DELETES: ' ..
                                   globals.config.TREND_SCORE_MORE_CREATES_THAN_DELETES['score'])
            end
        end

    end
end

-- TotalProcessScore tallies up the score of the entire process (parent/children).
-- If the parent-child score threshold is reached, an alert is generated. This
-- function also adds the trend score to the total score when the process trend
-- floor is reached.
-- @param eventData table: A table containing event data.
-- @param processData table: A table containing process data.
-- @return void.
function Production:TotalProcessScore(eventData, processData)
    processData.totalEventScore = processData.totalEventScore + eventData.alertScore
    processData.totalScore = processData.totalEventScore

    -- Parent process data score tallying.
    if globals.INVALID_PROCESS_ID ~= eventData.parentProcessId then
        -- No need to calculate a child score for an invalid parent.
        local parentProcessData = self.processDataTable[eventData.parentProcessId]
        parentProcessData.children[eventData.processId] = processData.totalScore
        local childScore = 0.0

        for _, v in pairs(parentProcessData.children) do
            childScore = childScore + v
        end

        utils.DebugLog('child Score: ' .. childScore)

        if (childScore >= globals.PROCESS_PARENT_CHILD_ALERT_SCORE_THRESHOLD) then
            utils.DebugLog('PARENT-CHILD ALERT: ' .. eventData.parentProcessId)
            parentProcessData.totalScore = parentProcessData.totalScore +
                                               globals.PROCESS_PARENT_CHILD_ALERT_SCORE_THRESHOLD

            if false == parentProcessData.alerted then
                utils.DebugLog('parentProcessData alert PID: ' .. parentProcessData.processId)

                -- If running with elastic endpoint, add child processes to parentProcessData.
                local product = utils.GetProduct()
                if product == 'elastic' then
                    -- Append the child processes alert data so we can capture
                    -- them in the 'Ransomware.child_processes' ECS field.
                    local ransomwareChildProcesses = {}
                    self:AppendChildProcesses(parentProcessData, ransomwareChildProcesses)
                    parentProcessData['child_processes'] = ransomwareChildProcesses
                end

                -- Generate parent alert for both endgame and elastic.
                alert.GenerateAlert(parentProcessData, true)
            end
        else
            utils.DebugLog('PPID ' .. eventData.parentProcessId .. ' | CHILD SCORE: ' .. childScore)
        end
    end

    if globals.PROCESS_TREND_FLOOR < #processData.events then
        if 0.0 < processData.trendScore then
            processData.totalScore = processData.totalScore + processData.trendScore
        end
    end

    utils.DebugLog('PID: ' .. eventData.processId .. ' | TOTAL #Events: ' .. #processData.events ..
                       ' | TOTAL Event Score: ' .. processData.totalEventScore .. ' | TOTAL Event + Trend Score: ' ..
                       processData.totalScore)
end

-- Main represents the entry point for this module. It calls several checks
-- that can identify ransomware activity. Each file operation can contribute
-- to the elevation of the score. When the score reaches the alert threshold,
-- an alert is generated and we stop monitoring the process. When a batch of
-- file events (200 window) is processed, a possibility of extension can take
-- place if certain conditions are met.
-- @inputData table: A table representing the input data.
-- @return: boolean: True always. TODO: fix the return value.
function Production:Main(inputData)
    local currentProcessData = nil
    local currentEventData = nil

    if not utils.TableHasKey(self.processDataTable, inputData.processId) then
        self.processDataTable[inputData.processId] = Ransomware.ProcessData(inputData.processId,
            inputData.parentProcessId)
    end

    currentProcessData = self.processDataTable[inputData.processId]

    if currentProcessData.activeAnalysis then
        currentEventData = self:EventData(inputData)
    else
        return true
    end

    if not utils.TableHasKey(self.processDataTable, currentEventData.parentProcessId) then
        -- Create a ProcessData object if one does not currently exist for the parent.
        -- At this point we do not know the identity of the process's parent, so
        -- it will be set to globals.INVALID_PROCESS_ID by default. This will be
        -- rectified later when an event belonging to this parent is analyzed
        -- (and its actual PPID is passed along).
        self.processDataTable[currentEventData.parentProcessId] = Ransomware.ProcessData(
            currentEventData.parentProcessId, globals.INVALID_PROCESS_ID)
    elseif currentProcessData.parentProcessId ~= currentEventData.parentProcessId then
        -- If PPIDs do not match, it's likely this ProcessData object was created earlier
        -- for an event originating from a child of this process (see if condition above).
        if currentProcessData.parentProcessId == globals.INVALID_PROCESS_ID then
            currentProcessData.parentProcessId = currentEventData.parentProcessId
        end
    end

    if not utils.TableHasValue(currentProcessData.uniqueDirectoriesByResponsibility, currentEventData.normalizedPath) then
        table.insert(currentProcessData.uniqueDirectoriesByResponsibility, currentEventData.normalizedPath)
    end

    -- Keep track of created file names.
    if currentEventData.operation == globals.FILE_CREATE_NEW then
        if not utils.TableHasKey(currentProcessData.createFileNames, currentEventData.fileName) then
            currentProcessData.createFileNames[currentEventData.fileName] = {}
        end
        table.insert(currentProcessData.createFileNames[currentEventData.fileName],
            {['fileExtension'] = currentEventData.fileExtension, ['filePath'] = currentEventData.filePath})

    end

    -- Zero out trend score.
    currentProcessData.trendScore = 0.0

    -- Duplicate Event Check.
    if self.DuplicateEventCheck(currentEventData, currentProcessData) then
        return true
    end

    -- Canary File Check.
    if (true == globals.canaryCompatible) and (true == globals.productionCanariesDropped) then
        -- If this is a qualifying canary event, the alert will be generated,
        -- so we can exit.
        if Ransomware:CanaryCheck(currentEventData, currentProcessData) then
            return true
        end
    end

    -- Header Check.
    self:HeaderCheck(currentEventData, currentProcessData)

    -- Entropy Check.
    self:EntropyCheck(currentEventData, currentProcessData)

    -- Path History.
    self.PathHistory(currentEventData, currentProcessData)

    -- Rename Check.
    if globals.FILE_RENAME == currentEventData.operation then
        self:RenameCheck(currentEventData)
    end

    -- Check for multiple extensions, odd characters in extension.
    self.AbnormalExtensionCheck(currentEventData, currentProcessData)

    -- Ransom Note Check.
    if globals.PROCESS_TREND_FLOOR < #currentProcessData.events then
        self.RansomNoteCheck(currentProcessData)
    end

    -- Tally up score for file on its own.
    self:TotalIndividualScore(currentEventData, currentProcessData)

    -- Process trend evaluation.
    if globals.PROCESS_TREND_FLOOR < #currentProcessData.events then
        self.TrendAnalysis(currentProcessData)
    end

    -- Update the process extension table.
    globals.UpdateExtensionTables(currentEventData, currentProcessData)

    -- Tally up score for the entire process.
    self:TotalProcessScore(currentEventData, currentProcessData)

    table.insert(currentProcessData.events, currentEventData)

    if globals.FILE_RENAME == currentEventData.operation then
        utils.DebugLog(currentEventData.operation .. ' | ' .. string.sub(currentEventData.entropy, 1, 4) .. ' | ' ..
                           currentEventData.alertScore .. '-' .. currentProcessData.totalEventScore .. ' ' ..
                           currentEventData.filePreviousPath .. ' => ' .. currentEventData.filePath)
    else
        utils.DebugLog(currentEventData.operation .. ' | ' .. string.sub(currentEventData.entropy, 1, 4) .. ' | ' ..
                           currentEventData.alertScore .. '-' .. currentProcessData.totalEventScore .. ' ' ..
                           currentEventData.filePath)
    end

    if globals.PROCESS_ALERT_SCORE_THRESHOLD <= currentProcessData.totalScore then
        -- Generate the alert as expected.
        alert.GenerateAlert(currentProcessData, self.diagnosticMode)

        -- Stop actively monitoring the process.
        self:StopActiveAnalysis(currentProcessData)

    elseif globals.PROCESS_EVENT_THRESHOLD == #currentProcessData.events then
        -- Check if we want to extend the event threshold for this process.
        if not self.ExtendEventThresholdCheck(currentProcessData) then
            self:SendStopActiveAnalysisMsg(currentProcessData)
        end
    elseif globals.PROCESS_EXTENDED_EVENT_THRESHOLD == #currentProcessData.events then
        -- Check if we want to extend the event threshold *again* for this process.
        if not self.ExtendEventThresholdCheck(currentProcessData) then
            self:SendStopActiveAnalysisMsg(currentProcessData)
        end
    elseif globals.PROCESS_FINAL_EXTENDED_EVENT_THRESHOLD == #currentProcessData.events then
        -- In this case we have reached the final process event threshold and
        -- still not alerted, so stop monitoring.
        self:SendStopActiveAnalysisMsg(currentProcessData)
    end

    return true
end


globals.namespaces = {Production}
globals.SwitchNamespace(Production)
