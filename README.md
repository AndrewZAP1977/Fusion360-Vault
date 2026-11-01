# F360 Vault
A Windows add-in for batch backup and export of Autodesk Fusion cloud projects. Select multiple designs, folders, or entire projects and export them all in a single operation.

## Install (Windows)
1. On GitHub, select **Code > Download ZIP** and extract the ZIP.
2. In Windows File Explorer, paste this into the address bar and press Enter:
   `%APPDATA%\Autodesk\Autodesk Fusion 360\API\AddIns`
3. From the extracted repository, copy **only the `F360Vault` folder** into `AddIns`.
   The resulting file path must be:
   `%APPDATA%\Autodesk\Autodesk Fusion 360\API\AddIns\F360Vault\F360Vault.manifest`
4. Open Fusion: **Utilities > Add-Ins > Scripts and Add-Ins > Add-Ins**.
   Select **F360Vault** and click **Run** (optionally enable **Run on Startup**).

## Use
1. Open **F360 Vault** in Fusion and select projects, folders, or individual designs in **Sources**.
2. In **Export**, choose a local folder, **Latest** or **All history**, and formats: **F3D/F3Z, STEP, STL, 3MF**.
3. Start the export. Existing backups are protected against overwriting; progress and reports are available in the add-in.

**IMPORTANT:** For large cloud libraries, the **Export** button may take time to become available while project data loads or settings are saved. After confirming an export, scanning cloud versions and checking existing backups can take a minute or longer before file processing starts. Fusion may appear unresponsive during this preparation; avoid restarting it or starting the export again.

**Linked assemblies (F3Z):** To back up complete assemblies with their linked components, click **Connect Autodesk** and sign in to your Autodesk account. This enables access through Autodesk Platform Services (APS). Without this connection, regular exports still work, but complete linked assemblies cannot be downloaded as F3Z files.

On manual updates, keep your existing `F360Vault/data` folder: it holds local settings and export history. The add-in does not include an installer.

Licensed under the [MIT License](LICENSE).
