Connect-ExchangeOnline

Get-DkimSigningConfig | Export-Csv c:\temp\SRC_Domains_DKIM_Config.csv


Connect-ExchangeOnline

Rotate-DkimSigningConfig -Identity southeastcollegeorg.onmicrosoft.com -KeySize 2048

Rotate-DkimSigningConfig -Identity southeastcollege.org -KeySize 2048