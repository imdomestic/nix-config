let
  # USD per million tokens; sources and effective dates: docs/pi-model-pricing.md.
  gpt = {
    input,
    output,
    cacheRead,
    cacheWrite,
    longOutput ? output * 1.5,
  }: {
    inherit input output cacheRead cacheWrite;
    tiers = [
      {
        inputTokensAbove = 272000;
        input = input * 2;
        output = longOutput;
        cacheRead = cacheRead * 2;
        cacheWrite = cacheWrite * 2;
      }
    ];
  };
  gemini = rates: rates // {cacheWrite = 0;};
in {
  "gpt-6.1-sol" = gpt {
    input = 2;
    output = 10;
    cacheRead = 0.1;
    cacheWrite = 2.5;
  };
  "gpt-6-astra" = gpt {
    input = 10;
    output = 50;
    cacheRead = 1;
    cacheWrite = 12.5;
  };
  "gpt-6-sol" = gpt {
    input = 2;
    output = 10;
    cacheRead = 0.2;
    cacheWrite = 2.5;
  };
  "gpt-6-luna" = gpt {
    input = 0.1;
    output = 0.5;
    cacheRead = 0.01;
    cacheWrite = 0.125;
  };
  "gpt-5.6-sol" = gpt {
    input = 4;
    output = 20;
    cacheRead = 0.4;
    cacheWrite = 5;
  };
  "gpt-5.6-terra" = gpt {
    input = 2;
    output = 12;
    cacheRead = 0.2;
    cacheWrite = 2.5;
  };
  "gpt-5.6-luna" = gpt {
    input = 0.2;
    output = 1.2;
    longOutput = 1.8;
    cacheRead = 0.02;
    cacheWrite = 0.25;
  };
  "gpt-5.5" = gpt {
    input = 5;
    output = 30;
    cacheRead = 0.5;
    cacheWrite = 0;
  };
  "gemini-3-flash" = gemini {
    input = 0.5;
    output = 3;
    cacheRead = 0.05;
  };
  "gemini-3.8-flash-high" = gemini {
    input = 0.75;
    output = 3.75;
    cacheRead = 0.075;
  };
  "gemini-3.1-flash-lite" = gemini {
    input = 0.25;
    output = 1.5;
    cacheRead = 0.025;
  };
  "gemini-3.5-flash-lite" = gemini {
    input = 0.3;
    output = 2.5;
    cacheRead = 0.03;
  };
}
