#pragma once

// Scan for engine symbols, find target UScriptStructs, and patch
// FCrLogisticsSocketsFragment's SuperStruct from FMassFragment to
// FCrMassSavableFragment.
bool ApplyPatch();
