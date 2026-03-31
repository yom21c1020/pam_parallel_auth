use zbus::Connection;
use zbus::zvariant::OwnedValue;

/// Check if the laptop lid is closed via logind D-Bus.
pub async fn is_lid_closed() -> Result<bool, String> {
    let connection = Connection::system()
        .await
        .map_err(|e| format!("D-Bus error: {e}"))?;

    let reply = connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(
                "org.freedesktop.login1.Manager",
                "LidClosed",
            ),
        )
        .await
        .map_err(|e| format!("logind query failed: {e}"))?;

    let value: OwnedValue = reply
        .body()
        .deserialize()
        .map_err(|e| format!("bad reply: {e}"))?;

    let closed: bool = value
        .try_into()
        .map_err(|_| "LidClosed not a bool".to_string())?;

    Ok(closed)
}
