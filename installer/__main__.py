import sys

if sys.argv[1:2] == ["pending"]:
    from .pending import main
    main()
else:
    from .web import main
    main()
