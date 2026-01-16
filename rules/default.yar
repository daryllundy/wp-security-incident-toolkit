rule WordPress_Backdoor {
    meta:
        description = "Detects WordPress backdoor patterns"
        author = "Daryl Lundy"
        date = "2024-01-01"
        severity = "high"

    strings:
        $backdoor1 = "eval(base64_decode"
        $backdoor2 = "system($_GET"
        $backdoor3 = "exec($_POST"
        $wp_pattern = "wp-config.php"

    condition:
        any of ($backdoor*) and $wp_pattern
}
