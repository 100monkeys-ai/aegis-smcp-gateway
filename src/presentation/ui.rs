use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

const UI_INDEX: &str = include_str!("ui_assets/index.html");
const UI_APP_JS: &str = include_str!("ui_assets/app.js");
const UI_STYLES: &str = include_str!("ui_assets/styles.css");

pub async fn index() -> Html<&'static str> {
    Html(UI_INDEX)
}

pub async fn app_js() -> Response {
    let mut response = (StatusCode::OK, UI_APP_JS).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    response
}

pub async fn styles_css() -> Response {
    let mut response = (StatusCode::OK, UI_STYLES).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    response
}
