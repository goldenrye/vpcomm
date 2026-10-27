import XCTest

final class InterfaceTests: XCTestCase {
    @MainActor func testInvitationAndInsecureAddress() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.textFields["address"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.buttons["start"].isEnabled)
        app.buttons["newInvitation"].tap()
        XCTAssertTrue(app.staticTexts["status"].label.contains("Invitation ready"))
        app.textFields["address"].tap()
        app.textFields["address"].typeText("ws://example.com/relay")
        app.secureTextFields["token"].tap()
        app.secureTextFields["token"].typeText(String(repeating: "a", count: 40))
        app.buttons["Done"].tap()
        app.buttons["start"].tap()
        XCTAssertTrue(app.staticTexts["status"].label.contains("Use wss://"))
        XCTAssertFalse(app.buttons["hangUp"].exists)
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
