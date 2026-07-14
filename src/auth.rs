#[derive(Default, Clone, Debug)]
pub struct AuthStore {
    pub cookies: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
}

impl AuthStore {
    pub fn from_cookie(cookie: &str) -> Self {
        let cookies = cookie
            .split(';')
            .filter_map(|c| {
                let c = c.trim();
                let mut parts = c.splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                    _ => None,
                }
            })
            .collect();
        AuthStore {
            cookies,
            headers: Vec::new(),
        }
    }

    pub fn from_headers(headers: &[String]) -> Self {
        let parsed: Vec<(String, String)> = headers
            .iter()
            .filter_map(|h| {
                let mut parts = h.splitn(2, ':');
                match (parts.next(), parts.next()) {
                    (Some(k), Some(v)) => Some((k.trim().to_string(), v.trim().to_string())),
                    _ => None,
                }
            })
            .collect();
        AuthStore {
            cookies: Vec::new(),
            headers: parsed,
        }
    }

    pub fn merge(&mut self, other: &AuthStore) {
        self.cookies.extend(other.cookies.clone());
        self.headers.extend(other.headers.clone());
    }

    pub fn apply_to_request(&self, request: &mut Vec<u8>) {
        let mut extra_headers: Vec<u8> = Vec::new();

        if !self.cookies.is_empty() {
            let cookie_val: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            extra_headers
                .extend_from_slice(format!("Cookie: {}\r\n", cookie_val.join("; ")).as_bytes());
        }

        for (name, value) in &self.headers {
            extra_headers.extend_from_slice(format!("{}: {}\r\n", name, value).as_bytes());
        }

        if let Some(pos) = find_header_end(request) {
            let mut new_req = request[..pos].to_vec();
            new_req.extend_from_slice(&extra_headers);
            new_req.extend_from_slice(&request[pos..]);
            *request = new_req;
        }
    }

    pub fn to_headers_vec(&self) -> Vec<(String, String)> {
        let mut all = self.headers.clone();
        if !self.cookies.is_empty() {
            let cookie_val: Vec<String> = self
                .cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            all.push(("Cookie".to_string(), cookie_val.join("; ")));
        }
        all
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}
