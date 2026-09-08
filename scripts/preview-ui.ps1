[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$uiRoot = Join-Path $projectRoot 'apps/desktop/ui'
$gallery = Join-Path $uiRoot 'preview/gallery.slint'
$viewer = (Get-Command slint-viewer -ErrorAction Stop).Source

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $projectRoot 'target/ui-preview'
}

$slintFiles = Get-ChildItem -LiteralPath $uiRoot -Filter '*.slint' -File -Recurse |
    Sort-Object -Property FullName
$componentByFile = @{
    'app-window.slint' = 'AppWindow'
    'components/window-controls.slint' = 'WindowControls'
    'components/brand.slint' = 'BrandLockup'
    'components/controls.slint' = 'AppButton'
    'components/glyph.slint' = 'Glyph'
    'components/sidebar.slint' = 'Sidebar'
    'components/smooth-card.slint' = 'SmoothCard'
    'components/update-dialog.slint' = 'UpdateDialog'
    'pages/about-page.slint' = 'AboutPage'
    'pages/home-page.slint' = 'HomePage'
    'pages/login-page.slint' = 'LoginPage'
    'pages/node-selector-sheet.slint' = 'NodeSelectorSheet'
    'pages/orders-page.slint' = 'OrdersPage'
    'pages/gift-card-page.slint' = 'GiftCardPage'
    'pages/invitation-page.slint' = 'InvitationPage'
    'pages/subscription-link-page.slint' = 'SubscriptionLinkPage'
    'pages/tickets-page.slint' = 'TicketsPage'
    'pages/account-settings-page.slint' = 'AccountSettingsPage'
    'pages/balance-details-sheet.slint' = 'BalanceDetailsPage'
    'pages/profile-page.slint' = 'ProfilePage'
    'pages/purchase-page.slint' = 'PurchasePage'
    'pages/settings-page.slint' = 'SettingsPage'
    'pages/subscriptions-page.slint' = 'SubscriptionsPage'
    'preview/gallery.slint' = 'DesignSystemPreview'
    'tray.slint' = 'AppTray'
}

foreach ($file in $slintFiles) {
    $relativePath = $file.FullName.Substring($uiRoot.Length + 1).Replace('\', '/')
    $component = $componentByFile[$relativePath]
    if ($null -eq $component) {
        # Data-only modules do not have a root component. The gallery imports
        # them and therefore remains the authoritative compile check.
        $component = 'DesignSystemPreview'
        $checkFile = $gallery
    } else {
        $checkFile = $file.FullName
    }
    & $viewer --style fluent --check --component $component $checkFile
    if ($LASTEXITCODE -ne 0) {
        throw "Slint check failed: $($file.FullName)"
    }
}

Write-Host "Checked $($slintFiles.Count) Slint files."

if ($CheckOnly) {
    return
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$previews = @(
    'TrayIconPreview',
    'LoginPreview',
    'LoginErrorPreview',
    'HomePreview',
    'NoNodeHomePreview',
    'CoreUnavailablePreview',
    'ConnectingPreview',
    'ConnectionFailedPreview',
    'ConnectedPreview',
    'StoppingPreview',
    'TelemetryStressPreview',
    'TelemetryDynamicPreview',
    'NodeSelectorPreview',
    'NodeSelectorErrorPreview',
    'SubscriptionsPreview',
    'SubscriptionsLoadingPreview',
    'SubscriptionsNoAddonPreview',
    'PurchasePreview',
    'PurchaseLoadingPreview',
    'PurchaseCheckoutConfirmPreview',
    'PurchaseCheckoutSinglePlanPreview',
    'PurchaseCheckoutPaymentPreview',
    'PurchaseCheckoutPaymentBusyPreview',
    'PurchaseCheckoutWaitingPreview',
    'PurchaseCheckoutBrowserWaitingPreview',
    'PurchaseCheckoutSuccessPreview',
    'PurchaseCheckoutAddonSuccessPreview',
    'ProfilePreview',
    'AboutPreview',
    'UpdatePreview',
    'StartupLoadingPreview',
    'StartupFailurePreview',
    'StartupUpdatePreview',
    'StartupRequiredUpdatePreview',
    'AutoLoginPreview',
    'ConfigBlocksAutoLoginPreview',
    'UpdateBlocksAutoLoginPreview',
    'RequiredUpdatePreview',
    'UpdateErrorPreview',
    'UnsupportedUpdatePreview',
    'LogoutConfirmationPreview',
    'AccountSettingsPreview',
    'AccountSettingsPasswordPreview',
    'AccountSettingsPasswordErrorPreview',
    'BalanceDetailsPreview',
    'OrdersPreview',
    'OrdersLoadingPreview',
    'OrdersEmptyPreview',
    'GiftCardPreview',
    'GiftCardLoadingPreview',
    'GiftCardCheckedPreview',
    'GiftCardUnavailablePreview',
    'GiftCardRedeemErrorPreview',
    'GiftCardSuccessPreview',
    'InvitationPreview',
    'InvitationLoadingPreview',
    'InvitationEmptyPreview',
    'InvitationPausedPreview',
    'InvitationMorePreview',
    'InvitationStickyPreview',
    'SubscriptionLinkPreview',
    'SubscriptionLinkLoadingPreview',
    'SubscriptionLinkErrorPreview',
    'SubscriptionLinkResetPreview',
    'TicketsPreview',
    'TicketChatPreview',
    'TicketWindowChatPreview',
    'TicketCloseConfirmationPreview',
    'TicketCreatePreview',
    'TicketWindowCreatePreview',
    'SettingsPreview',
    'GlobalModeSettingsPreview',
    'PermissionRequestSettingsPreview',
    'ApplyingSettingsPreview',
    'DesignSystemPreview'
)

foreach ($component in $previews) {
    $screenshot = Join-Path $OutputDirectory "$component.png"
    & $viewer --style fluent --component $component --screenshot $screenshot $gallery
    if ($LASTEXITCODE -ne 0) {
        throw "Slint screenshot failed: $component"
    }
}

Write-Host "Rendered $($previews.Count) previews to $OutputDirectory."
