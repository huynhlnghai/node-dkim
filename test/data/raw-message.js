module.exports = `Delivered-To: nmarcellin2@gmail.com
Received: by 10.31.58.196 with SMTP id h187csp9975137vka;
        Sun, 22 Oct 2017 07:00:21 -0700 (PDT)
X-Received: by 10.200.15.136 with SMTP id b8mr16200104qtk.64.1508680821924;
        Sun, 22 Oct 2017 07:00:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1508680821; cv=none;
        d=google.com; s=arc-20160816;
        b=uk32DQIl/REjMUaP6Yq6JYBSTIGqKC2o96BtF5Y6UK6AAwOAUv4j/sUxFXoL5pBSet
         /CGHGfFD7Gu5qv8mtPYRM2imXZBBObx67eyx8+31dDQ/Ca30Oc8gVJ1xmm5IVZ0tAOje
         Y639munmN3E4TJruT+OiQNlvZZvJN0KyShaQ+gCCIgFAhtEm/YxipioOG8qKloAUC4bh
         xSFUny3+LhnqRW3Y5VTBVF5kUu8hyfI5Nc4NWg4DnCn2I3Gyc0olqlU2d/2QqKUXNeCn
         +BwHL7GcfTwZ60e0LvEserh8ecTsDuu+iIpjPlcu4wJuCPhjDFvxbtd6xucawT8x/MBW
         J9Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature
         :arc-authentication-results;
        bh=9w2H8ucfF1w3+Zqu9gpPcHgTU9GHPjw7E2HYHHlZEkw=;
        b=Y3kwptsKTOHCqiQenR9ptJ7blxDYtJbi+0+uYn+Aw8LC6Kk9OkczBzzjFPHXWGa//q
         K6V0kufbCZ0YPEkU14b0ZIexVFIbIiI7TAPOTDZzrMPEjkhh1D9nKsl3gt120eyli2Hf
         /IkGCnHcKW87+Qipt68pjd39cD+zun3VSdcXD/vvkvhchNdjvDVwyRzJN2xMbVzQ33cR
         SA/5ZZEAnhrk2w1+tY5Mldel7HOJI0sICOUXOBQQUumY9Z9lKlUs0vXadByNzlJO3S+U
         onH3xTIzUc5uB/5Zoga4QBLdeDUUlSBPM6QaYc3NDi7nrnqPfalkVBa+jMLYQpXUfx6/
         mfNg==
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@fusemachines.com header.s=google header.b=iPc3RHh9;
       spf=pass (google.com: domain of mars@fusemachines.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=mars@fusemachines.com
Return-Path: <mars@fusemachines.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id r6sor3780530qti.153.2017.10.22.07.00.21
        for <nmarcellin2@gmail.com>
        (Google Transport Security);
        Sun, 22 Oct 2017 07:00:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of mars@fusemachines.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@fusemachines.com header.s=google header.b=iPc3RHh9;
       spf=pass (google.com: domain of mars@fusemachines.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=mars@fusemachines.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=fusemachines.com; s=google;
        h=mime-version:from:date:message-id:subject:to;
        bh=9w2H8ucfF1w3+Zqu9gpPcHgTU9GHPjw7E2HYHHlZEkw=;
        b=iPc3RHh9oXL6+dvuPM0hYt1vdj6U4hN83BFxhumWsSXnFDFmbSG4OtXHPF823HoZAA
         4MbFQu5VgfvAQ+FmnKyfON2WdJrAYicyslVXlcA6l0UKSGIH/0NHSqi/kX+4KEKaClY7
         jZkXZZ8EIl5IUBdRRUWSsySFOtrQ/9IeAb6YM=
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to;
        bh=9w2H8ucfF1w3+Zqu9gpPcHgTU9GHPjw7E2HYHHlZEkw=;
        b=gaapyixgX52/f91ifJ2hxRuk13TLcG1ZKUo+Ci3j5a6rKCISPtmLXxwaXq5tghh5qg
         r7S/oe5nDijJmdo1pIBDYGf9U+IDgIT9jHxP3pUoLwmhgnO3pr1di1JH0361ogIsGq/W
         wATmvMTeEA1jAnKw8sr9Rb+jl2MUhqZLhL5Lhkdx/l5CCI0mfUmRAuv1XvGKdrPexM00
         4UTNx9VeK8qYQ/jdf1BiX0ICrj/7e5hSImZ44ctHzn/HA3Htur6cBdFlAVHpW5/vPj0q
         xnz5KQATcG0GmTX2rF27SGhAyPzRl+CZ0SDg9cGV2CvQ5kbDxsxOdzotR2X4hqksqMcC
         S+EQ==
X-Gm-Message-State: AMCzsaVGkvHZbfZofPrsj3QKBCLwg3nAsBM8cWdu5BXU7v1zENATSRJC uiG27aeGnsU8HjTsRFYk1HqnrNYGNuxg5R7wfRrnRw==
X-Google-Smtp-Source: ABhQp+RznzRtpIGeOvxieUGeSxwDHEfX8SuSwMwZJSlXyU4GyjbzDw6PsT5DOScWWomiALUIa/1ktC1p5vFEDe7HcH8=
X-Received: by 10.200.3.87 with SMTP id w23mr15494938qtg.98.1508680821032; Sun, 22 Oct 2017 07:00:21 -0700 (PDT)
MIME-Version: 1.0
Received: by 10.12.141.15 with HTTP; Sun, 22 Oct 2017 07:00:00 -0700 (PDT)
From: Marcellin Nshimiyimana <mars@fusemachines.com>
Date: Sun, 22 Oct 2017 19:45:00 +0545
Message-ID: <CAOwpMi-cqMgYZ4BqFeP2QASdS54oqQ6diFfFQn+eVAVhHEC4yw@mail.gmail.com>
Subject: Test email
To: Mars-sprint <nmarcellin2@gmail.com>
Content-Type: multipart/alternative; boundary="f4030435c3286adbf3055c232081"

--f4030435c3286adbf3055c232081
Content-Type: text/plain; charset="UTF-8"

Hello

--f4030435c3286adbf3055c232081
Content-Type: text/html; charset="UTF-8"

<div dir="ltr">Hello</div>

--f4030435c3286adbf3055c232081--

`;