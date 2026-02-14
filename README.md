# Automated-SuperISOUpdater
PowerShell Script for Automated Python & SuperISOUpdater Installation + Ventoy Drive Detection & ISO Updates

Thanks to [Joshua Vandaële](https://github.com/JoshuaVandaele) for creating [SuperISOUpdater](https://github.com/JoshuaVandaele/SuperISOUpdater), and to the [Ventoy project](https://github.com/ventoy/Ventoy) team for making it possible to manage bootable USB drives with ease.

## Ventoy Installation Requirement

Before using this script, **Ventoy must be installed** on the drive you plan to use. Ventoy allows you to boot from multiple ISO files from a single USB drive, and it is an essential component for this script to work effectively.

You can download and install Ventoy from their official repository [here](https://github.com/ventoy/Ventoy). Follow the installation instructions provided to set up Ventoy on your USB drive.

## PowerShell Execution Policy

Before running this script, ensure that your PowerShell execution policy allows script execution. You can do this by running the following command in an elevated PowerShell (run as Administrator):

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Revival roadmap

A concrete recovery plan for this project is tracked in [`REVIVAL_PLAN.md`](./REVIVAL_PLAN.md).
