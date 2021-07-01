//
//  ViewController.swift
//  Proxy
//
//  Created by John Lenon Reis on 10/03/21.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    @IBAction func testProxy(_ sender: Any) {
        let url = URL(string: "https://api.umov.me/CenterWeb/api/2159e486a03a268d015caa72b19af0cc10d10/activity.xml?id=1035444")!
        HttpConnector().connect(to: url)
    }
}
